use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use gix_object::{
    Commit, WriteTo,
    commit::signature::{Format, Options},
};
use gix_testtools::signature;

use crate::Result;

#[test]
fn ssh() -> Result {
    if !signature::program_available("ssh-keygen") {
        return Ok(());
    }
    let (key_home, key) = signature::ssh_private_key()?;
    let signed = commit().sign(Options {
        format: Format::Ssh,
        program: "ssh-keygen".into(),
        program_arguments: Vec::new(),
        signing_key: key.into_os_string(),
        environment: Vec::new(),
    })?;
    verify_ssh(&signed, &signature::fixture("ssh-allowed-signers"))?;
    drop(key_home);
    Ok(())
}

#[test]
fn openpgp() -> Result {
    if !signature::program_available("gpg") {
        return Ok(());
    }
    let home = signature::openpgp_home()?;
    let signed = commit().sign(Options {
        format: Format::OpenPgp,
        program: "gpg".into(),
        program_arguments: vec!["--pinentry-mode=error".into()],
        signing_key: signature::IDENTITY.into(),
        environment: vec![("GNUPGHOME".into(), home.path().as_os_str().to_owned())],
    })?;
    verify_gpg(&signed, "gpg", home.path())?;
    Ok(())
}

#[test]
fn x509() -> Result {
    if !signature::program_available("gpgsm") {
        return Ok(());
    }
    let home = signature::x509_home()?;
    let signed = commit().sign(Options {
        format: Format::X509,
        program: "gpgsm".into(),
        program_arguments: Vec::new(),
        signing_key: signature::IDENTITY.into(),
        environment: vec![("GNUPGHOME".into(), home.path().as_os_str().to_owned())],
    })?;
    verify_gpg(&signed, "gpgsm", home.path())?;
    Ok(())
}

#[test]
fn replaces_the_active_signature() -> Result {
    if !signature::program_available("ssh-keygen") {
        return Ok(());
    }
    let (key_home, key) = signature::ssh_private_key()?;
    let mut commit = commit();
    commit.extra_headers.push(("before".into(), "one".into()));
    commit.extra_headers.push(("gpgsig".into(), "old".into()));
    commit.extra_headers.push(("after".into(), "two".into()));
    let signed = commit.sign(Options {
        format: Format::Ssh,
        program: "ssh-keygen".into(),
        program_arguments: Vec::new(),
        signing_key: key.into_os_string(),
        environment: Vec::new(),
    })?;
    assert_eq!(
        signed
            .extra_headers
            .iter()
            .map(|(name, _)| name.as_slice())
            .collect::<Vec<_>>(),
        [b"before".as_slice(), b"after".as_slice(), b"gpgsig".as_slice()],
        "the old active signature is removed and its replacement is appended like Git"
    );
    verify_ssh(&signed, &signature::fixture("ssh-allowed-signers"))?;
    drop(key_home);
    Ok(())
}

#[test]
fn sha256_uses_its_git_signature_header() -> Result {
    if !signature::program_available("ssh-keygen") {
        return Ok(());
    }
    let (key_home, key) = signature::ssh_private_key()?;
    let mut commit = commit();
    commit.tree = gix_hash::ObjectId::empty_tree(gix_hash::Kind::Sha256);
    let signed = commit.sign(Options {
        format: Format::Ssh,
        program: "ssh-keygen".into(),
        program_arguments: Vec::new(),
        signing_key: key.into_os_string(),
        environment: Vec::new(),
    })?;
    assert_eq!(signed.extra_headers[0].0, "gpgsig-sha256");
    verify_ssh(&signed, &signature::fixture("ssh-allowed-signers"))?;
    drop(key_home);
    Ok(())
}

fn commit() -> Commit {
    let actor = gix_actor::Signature {
        name: "Gitoxide Signing Fixture".into(),
        email: signature::IDENTITY.into(),
        time: gix_date::Time::new(1_700_000_000, 0),
    };
    Commit {
        tree: gix_hash::ObjectId::empty_tree(gix_hash::Kind::Sha1),
        parents: Default::default(),
        author: actor.clone(),
        committer: actor,
        encoding: None,
        message: "signed commit\n".into(),
        extra_headers: Vec::new(),
    }
}

fn signed_parts(commit: &Commit) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    commit.write_to(&mut data)?;
    let (signature, signed) =
        gix_object::CommitRefIter::signature(&data, commit.tree.kind())?.expect("the commit was just signed");
    Ok((signature.into_owned().into(), signed.to_bstring().into()))
}

fn verify_ssh(commit: &Commit, allowed_signers: &Path) -> Result {
    let (signature, signed) = signed_parts(commit)?;
    let mut signature_file = gix_testtools::tempfile::NamedTempFile::new()?;
    signature_file.write_all(&signature)?;
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(allowed_signers)
        .args(["-I", signature::IDENTITY, "-n", "git", "-s"])
        .arg(signature_file.path())
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("configured as piped").write_all(&signed)?;
    assert!(child.wait()?.success(), "ssh-keygen accepts the generated signature");
    Ok(())
}

fn verify_gpg(commit: &Commit, program: &str, home: &Path) -> Result {
    let (signature, signed) = signed_parts(commit)?;
    let mut signature_file = gix_testtools::tempfile::NamedTempFile::new()?;
    signature_file.write_all(&signature)?;
    let mut command = Command::new(program);
    command
        .args(["--batch", "--homedir"])
        .arg(home)
        .arg("--verify")
        .arg(signature_file.path());
    let mut signed_file = None;
    if program == "gpgsm" {
        let mut file = gix_testtools::tempfile::NamedTempFile::new()?;
        file.write_all(&signed)?;
        command.arg(file.path()).stdin(Stdio::null());
        signed_file = Some(file);
    } else {
        command.arg("-").stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&signed)?;
    }
    assert!(child.wait()?.success(), "the signer verifies its generated signature");
    drop(signed_file);
    Ok(())
}
