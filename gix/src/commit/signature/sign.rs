use std::{ffi::OsString, process::Stdio};

use crate::bstr::{BString, ByteSlice};
use crate::config::tree::{Gpg, User, gpg};

use super::Format;

/// Errors encountered when applying resolved signing options to a commit.
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum Error {
    #[error(transparent)]
    Options(#[from] options::Error),
    #[error(transparent)]
    Decode(#[from] gix_object::decode::Error),
    #[error(transparent)]
    Sign(#[from] gix_object::commit::signature::Error),
}

/// Resolve Git-compatible commit-signing options from repository configuration.
pub mod options {
    use super::*;

    /// The error returned by [`crate::Repository::commit_signing_options()`].
    #[derive(Debug, thiserror::Error)]
    #[expect(missing_docs)]
    pub enum Error {
        #[error(transparent)]
        ConfigBoolean(#[from] crate::config::boolean::Error),
        #[error(transparent)]
        ParseTime(#[from] crate::config::time::Error),
        #[error("Unsupported value for gpg.format: {0:?}")]
        UnsupportedFormat(BString),
        #[error("Committer identity is not configured and user.signingKey is unset")]
        MissingCommitter,
        #[error("user.signingKey or gpg.ssh.defaultKeyCommand must provide an SSH signing key")]
        MissingSshSigningKey,
        #[error("Could not interpolate a configured commit-signing path")]
        ConfiguredPath(#[from] gix_config::path::interpolate::Error),
        #[error("Could not execute gpg.ssh.defaultKeyCommand {program:?}")]
        DefaultKeyCommand {
            program: OsString,
            #[source]
            source: std::io::Error,
        },
        #[error("gpg.ssh.defaultKeyCommand failed: {0:?}")]
        DefaultKeyCommandFailed(BString),
        #[error("gpg.ssh.defaultKeyCommand returned an invalid key: {0:?}")]
        InvalidDefaultKey(BString),
    }
}

pub(crate) fn sign(commit: &crate::Commit<'_>) -> Result<gix_object::Commit, Error> {
    let options = commit.repo.commit_signing_options()?;
    commit.decode()?.sign(options).map_err(Into::into)
}

pub(crate) fn options(repo: &crate::Repository) -> Result<gix_object::commit::signature::Options, options::Error> {
    let config = repo.config_snapshot();
    let format = config
        .string(Gpg::FORMAT)
        .map(|value| parse_format(value.trim()).ok_or(options::Error::UnsupportedFormat(value)))
        .transpose()?
        .unwrap_or(Format::OpenPgp);
    let program = match format {
        Format::OpenPgp => match config.trusted_path(gpg::OpenPgp::PROGRAM)? {
            Some(program) => program.into_os_string(),
            None => config
                .trusted_path(Gpg::PROGRAM)?
                .map_or_else(|| "gpg".into(), std::path::PathBuf::into_os_string),
        },
        Format::X509 => config
            .trusted_path(gpg::X509::PROGRAM)?
            .map_or_else(|| "gpgsm".into(), std::path::PathBuf::into_os_string),
        Format::Ssh => config
            .trusted_path(gpg::Ssh::PROGRAM)?
            .map_or_else(|| "ssh-keygen".into(), std::path::PathBuf::into_os_string),
    };
    let signing_key = match config.string(User::SIGNING_KEY) {
        Some(key) if !key.is_empty() && format == Format::Ssh && !is_literal_ssh_key(&key) => {
            config.trusted_path(User::SIGNING_KEY)?.map_or_else(
                || gix_path::from_bstring(key).into_os_string(),
                std::path::PathBuf::into_os_string,
            )
        }
        Some(key) if !key.is_empty() => gix_path::from_bstring(key).into_os_string(),
        _ if format == Format::Ssh => default_ssh_key(&config)?.ok_or(options::Error::MissingSshSigningKey)?,
        _ => {
            let committer = repo.committer().ok_or(options::Error::MissingCommitter)??;
            let mut identity = committer.name.to_owned();
            identity.extend_from_slice(b" <");
            identity.extend_from_slice(committer.email);
            identity.extend_from_slice(b">");
            gix_path::from_bstring(identity).into_os_string()
        }
    };
    Ok(gix_object::commit::signature::Options {
        format,
        program,
        program_arguments: Vec::new(),
        signing_key,
        environment: Vec::new(),
    })
}

pub(crate) fn options_if_enabled(
    repo: &crate::Repository,
) -> Result<Option<gix_object::commit::signature::Options>, options::Error> {
    repo.config.may_sign_commits()?.then(|| options(repo)).transpose()
}

fn parse_format(value: &[u8]) -> Option<Format> {
    if value.eq_ignore_ascii_case(b"openpgp") {
        Some(Format::OpenPgp)
    } else if value.eq_ignore_ascii_case(b"x509") {
        Some(Format::X509)
    } else if value.eq_ignore_ascii_case(b"ssh") {
        Some(Format::Ssh)
    } else {
        None
    }
}

fn is_literal_ssh_key(key: &[u8]) -> bool {
    key.starts_with(b"ssh-") || key.starts_with(b"key::")
}

fn default_ssh_key(config: &crate::config::Snapshot<'_>) -> Result<Option<OsString>, options::Error> {
    let Some(program) = config.trusted_program(gpg::Ssh::DEFAULT_KEY_COMMAND) else {
        return Ok(None);
    };
    let output = gix_command::prepare(&program)
        .command_may_be_shell_script()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| options::Error::DefaultKeyCommand {
            program: program.clone(),
            source,
        })?
        .wait_with_output()
        .map_err(|source| options::Error::DefaultKeyCommand {
            program: program.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(options::Error::DefaultKeyCommandFailed(output.stderr.into()));
    }
    let key = output.stdout.as_bstr().lines().next().unwrap_or_default().trim();
    if !is_literal_ssh_key(key) {
        return Err(options::Error::InvalidDefaultKey(key.into()));
    }
    Ok(Some(gix_path::from_bstr(key.as_bstr()).into_owned().into_os_string()))
}
