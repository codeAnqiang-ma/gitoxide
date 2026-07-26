#[cfg(feature = "revision")]
mod describe {
    use gix::commit::describe::SelectRef::{AllRefs, AllTags, AnnotatedTags};

    use crate::named_repo;

    #[cfg(feature = "status")]
    mod with_dirty_suffix {
        use gix::commit::describe::SelectRef;

        use crate::util::named_subrepo_opts;

        #[test]
        fn dirty_suffix_applies_automatically_if_dirty() -> crate::Result {
            let repo = named_subrepo_opts(
                "make_submodules.sh",
                "submodule-head-changed",
                gix::open::Options::isolated(),
            )?;

            let actual = repo
                .head_commit()?
                .describe()
                .names(SelectRef::AllRefs)
                .try_resolve()?
                .expect("resolution")
                .format_with_dirty_suffix("dirty".to_owned())?
                .to_string();
            assert_eq!(actual, "main-dirty");
            Ok(())
        }

        #[test]
        fn dirty_suffix_does_not_apply_if_not_dirty() -> crate::Result {
            let repo = named_subrepo_opts("make_submodules.sh", "module1", gix::open::Options::isolated())?;

            let actual = repo
                .head_commit()?
                .describe()
                .names(SelectRef::AllRefs)
                .try_resolve()?
                .expect("resolution")
                .format_with_dirty_suffix("dirty".to_owned())?
                .to_string();
            assert_eq!(actual, "main");
            Ok(())
        }
    }

    #[test]
    fn tags_are_sorted_by_date_and_lexicographically() -> crate::Result {
        let repo = named_repo("make_commit_describe_multiple_tags.sh")?;
        let mut describe = repo.head_commit()?.describe();
        for filter in &[AnnotatedTags, AllTags, AllRefs] {
            describe = describe.names(*filter);
            assert_eq!(describe.format()?.to_string(), "v4", "{filter:?}");
        }
        Ok(())
    }

    #[test]
    fn tags_are_sorted_by_priority() -> crate::Result {
        let repo = named_repo("make_commit_describe_multiple_tags.sh")?;
        let commit = repo.find_reference("refs/tags/v0")?.id().object()?.into_commit();
        let mut describe = commit.describe();
        for filter in &[AnnotatedTags, AllTags, AllRefs] {
            describe = describe.names(*filter);
            assert_eq!(describe.format()?.to_string(), "v1", "{filter:?}");
        }
        Ok(())
    }

    #[test]
    fn lightweight_tags_are_sorted_lexicographically() -> crate::Result {
        let repo = named_repo("make_commit_describe_multiple_tags.sh")?;
        let commit = repo.find_reference("refs/tags/l0")?.id().object()?.into_commit();
        let mut describe = commit.describe();
        for filter in &[AnnotatedTags, AllTags, AllRefs] {
            describe = describe.names(*filter);
            let expected = match filter {
                AnnotatedTags => None,
                _ => Some("l0"),
            };
            let actual = describe.try_format()?.map(|f| f.to_string());
            assert_eq!(actual.as_deref(), expected, "{filter:?}");
        }
        Ok(())
    }
}

#[cfg(feature = "command")]
mod signature {
    use std::process::Command;

    use gix_testtools::signature;

    #[test]
    fn verifies_a_commit_signed_by_git_with_ssh() -> crate::Result {
        if !signature::program_available("ssh-keygen") {
            return Ok(());
        }
        let (_key_home, key) = signature::ssh_private_key()?;
        let fixture = gix_testtools::scripted_fixture_writable("make_basic_repo.sh")?;
        let output = Command::new("git")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", if cfg!(windows) { "NUL" } else { "/dev/null" })
            .env("GIT_CONFIG_COUNT", "0")
            .arg("-C")
            .arg(fixture.path())
            .args(["-c", "user.name=Gitoxide Signing Fixture", "-c"])
            .arg(format!("user.email={}", signature::IDENTITY))
            .args(["-c", "gpg.format=ssh", "-c"])
            .arg(format!("user.signingKey={}", key.display()))
            .args(["commit", "--allow-empty", "-S", "-m", "signed by Git"])
            .output()?;
        assert!(
            output.status.success(),
            "Git creates the reference signature: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let repo = gix::open_opts(
            fixture.path(),
            gix::open::Options::isolated().config_overrides([format!(
                "gpg.ssh.allowedSignersFile={}",
                signature::fixture("ssh-allowed-signers").display()
            )]),
        )?;
        let outcome = repo
            .head_commit()?
            .verify_signature()?
            .expect("Git created a signed commit");
        assert!(outcome.is_valid(), "the Git-generated signature is valid");
        assert_eq!(outcome.format, gix::commit::signature::Format::Ssh);
        assert_eq!(
            outcome.signer.as_ref().map(|signer| signer.as_slice()),
            Some(signature::IDENTITY.as_bytes())
        );
        Ok(())
    }
}
