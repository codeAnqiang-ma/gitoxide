use std::ffi::OsStr;

use gix_testtools::Env;
use serial_test::serial;

fn repository(
    overrides: impl IntoIterator<Item = impl Into<gix::bstr::BString>>,
) -> gix_testtools::Result<gix::Repository> {
    let fixture = gix_testtools::scripted_fixture_read_only("make_config_repos.sh")?;
    let mut permissions = gix::open::Permissions::isolated();
    permissions.env.git_prefix = gix::sec::Permission::Allow;
    Ok(gix::open_opts(
        fixture.join("http-proxy-empty"),
        gix::open::Options::isolated()
            .permissions(permissions)
            .config_overrides(overrides),
    )?)
}

#[test]
#[serial]
fn follows_git_editor_precedence() -> gix_testtools::Result {
    let _env = Env::new()
        .set("TERM", "xterm")
        .set("GIT_EDITOR", ":")
        .set("VISUAL", "visual")
        .set("EDITOR", "editor");
    assert_eq!(
        repository(["core.editor=core"])?.editor().as_deref(),
        Some(OsStr::new(":"))
    );

    let _env = Env::new().unset("GIT_EDITOR");
    assert_eq!(
        repository(["core.editor=core"])?.editor().as_deref(),
        Some(OsStr::new("core"))
    );
    assert_eq!(
        repository([] as [&str; 0])?.editor().as_deref(),
        Some(OsStr::new("visual"))
    );

    let _env = Env::new().unset("VISUAL");
    assert_eq!(
        repository([] as [&str; 0])?.editor().as_deref(),
        Some(OsStr::new("editor"))
    );

    let _env = Env::new().unset("EDITOR");
    assert_eq!(repository([] as [&str; 0])?.editor().as_deref(), Some(OsStr::new("vi")));
    Ok(())
}

#[test]
#[serial]
fn dumb_terminals_require_an_explicit_non_visual_editor() -> gix_testtools::Result {
    let _env = Env::new()
        .set("TERM", "dumb")
        .unset("GIT_EDITOR")
        .set("VISUAL", "visual")
        .unset("EDITOR");
    assert_eq!(repository([] as [&str; 0])?.editor(), None);

    let _env = Env::new().set("EDITOR", "editor");
    assert_eq!(
        repository([] as [&str; 0])?.editor().as_deref(),
        Some(OsStr::new("editor"))
    );
    Ok(())
}

#[test]
#[serial]
fn isolated_repositories_ignore_editor_environment() -> gix_testtools::Result {
    let fixture = gix_testtools::scripted_fixture_read_only("make_config_repos.sh")?;
    let _env = Env::new()
        .set("TERM", "xterm")
        .set("GIT_EDITOR", "git-editor")
        .set("VISUAL", "visual")
        .set("EDITOR", "editor");
    let repository = gix::open_opts(fixture.join("http-proxy-empty"), gix::open::Options::isolated())?;
    assert_eq!(repository.editor().as_deref(), Some(OsStr::new("vi")));
    Ok(())
}
