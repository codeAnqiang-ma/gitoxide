use crate::config::{
    self,
    tree::{Key, Section, keys},
};

impl super::Gpg {
    /// The `gpg.format` key.
    pub const FORMAT: keys::Any = keys::Any::new("format", &config::Tree::GPG);
    /// The legacy `gpg.program` key used as an OpenPGP program fallback.
    pub const PROGRAM: keys::Program = keys::Program::new_program("program", &config::Tree::GPG);
    /// The `gpg.minTrustLevel` key.
    pub const MIN_TRUST_LEVEL: keys::Any = keys::Any::new("minTrustLevel", &config::Tree::GPG);
    /// The `gpg.openpgp` subsection.
    pub const OPENPGP: OpenPgp = OpenPgp;
    /// The `gpg.x509` subsection.
    pub const X509: X509 = X509;
    /// The `gpg.ssh` subsection.
    pub const SSH: Ssh = Ssh;
}

impl Section for super::Gpg {
    fn name(&self) -> &str {
        "gpg"
    }
    fn keys(&self) -> &[&dyn Key] {
        &[&Self::FORMAT, &Self::PROGRAM, &Self::MIN_TRUST_LEVEL]
    }
    fn sub_sections(&self) -> &[&dyn Section] {
        &[&Self::OPENPGP, &Self::X509, &Self::SSH]
    }
}

/// The `gpg.openpgp` subsection.
#[derive(Copy, Clone, Default)]
pub struct OpenPgp;
impl OpenPgp {
    /// The `gpg.openpgp.program` key.
    pub const PROGRAM: keys::Program = keys::Program::new_program("program", &super::Gpg::OPENPGP);
}
impl Section for OpenPgp {
    fn name(&self) -> &str {
        "openpgp"
    }
    fn keys(&self) -> &[&dyn Key] {
        &[&Self::PROGRAM]
    }
    fn parent(&self) -> Option<&dyn Section> {
        Some(&config::Tree::GPG)
    }
}

/// The `gpg.x509` subsection.
#[derive(Copy, Clone, Default)]
pub struct X509;
impl X509 {
    /// The `gpg.x509.program` key.
    pub const PROGRAM: keys::Program = keys::Program::new_program("program", &super::Gpg::X509);
}
impl Section for X509 {
    fn name(&self) -> &str {
        "x509"
    }
    fn keys(&self) -> &[&dyn Key] {
        &[&Self::PROGRAM]
    }
    fn parent(&self) -> Option<&dyn Section> {
        Some(&config::Tree::GPG)
    }
}

/// The `gpg.ssh` subsection.
#[derive(Copy, Clone, Default)]
pub struct Ssh;
impl Ssh {
    /// The `gpg.ssh.program` key.
    pub const PROGRAM: keys::Program = keys::Program::new_program("program", &super::Gpg::SSH);
    /// The `gpg.ssh.defaultKeyCommand` key.
    pub const DEFAULT_KEY_COMMAND: keys::Program = keys::Program::new_program("defaultKeyCommand", &super::Gpg::SSH);
    /// The `gpg.ssh.allowedSignersFile` key.
    pub const ALLOWED_SIGNERS_FILE: keys::Path = keys::Path::new_path("allowedSignersFile", &super::Gpg::SSH);
    /// The `gpg.ssh.revocationFile` key.
    pub const REVOCATION_FILE: keys::Path = keys::Path::new_path("revocationFile", &super::Gpg::SSH);
}
impl Section for Ssh {
    fn name(&self) -> &str {
        "ssh"
    }
    fn keys(&self) -> &[&dyn Key] {
        &[
            &Self::PROGRAM,
            &Self::DEFAULT_KEY_COMMAND,
            &Self::ALLOWED_SIGNERS_FILE,
            &Self::REVOCATION_FILE,
        ]
    }
    fn parent(&self) -> Option<&dyn Section> {
        Some(&config::Tree::GPG)
    }
}
