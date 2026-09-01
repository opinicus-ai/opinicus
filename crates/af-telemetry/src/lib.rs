//! Redaction-first packaging of optional telemetry samples.
//!
//! The direction of record asks for early-access telemetry that is opt-in,
//! granular and revocable, whose content a user can inspect before anything
//! leaves the machine ([DIRECTION.md §7]). This crate is the packaging half
//! of that promise: it reads the events of one recorded session and writes
//! **samples** — small, redacted, pseudonymized extracts around the events
//! that made the firewall ask, quarantine or refuse.
//!
//! What this crate deliberately has, and has not:
//!
//! * It **has** a consent store ([`Consent`]): off by default, granular over
//!   [`Scope`]s, revocable, kept in one local file that no other part of the
//!   firewall reads. With telemetry off the product is complete.
//! * It **has** redaction by design ([`redaction`]): the environment-value
//!   redaction of the monitor ([RESEARCH.md §4]) generalized to every free
//!   text a sample can carry, plus pseudonymization of the identifiers that
//!   name the user, the machine and the session.
//! * It **has not** any network code. No socket, no client, no sender exists
//!   here or anywhere in the workspace. A sample is written to a local
//!   **outbox** directory as plain JSON, where the user can inspect it and
//!   destroy it. The research backend of [DIRECTION.md §8] is future work
//!   and nothing in this crate calls it, stubs it or prepares it.
//!
//! [DIRECTION.md §7]: https://github.com/opinicus-ai/opinicus/blob/main/docs/DIRECTION.md
//! [DIRECTION.md §8]: https://github.com/opinicus-ai/opinicus/blob/main/docs/DIRECTION.md
//! [RESEARCH.md §4]: https://github.com/opinicus-ai/opinicus/blob/main/docs/RESEARCH.md

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod redaction;
pub mod report;
pub mod sample;
mod sha256;

use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use report::{build_report, write_report, FalsePositiveReport, REPORT_SCHEMA};
pub use sample::{
    build_samples, default_outbox_path, list_samples, write_sample, AgentIdentity, Options,
    ProcessNode, Sample, SampleReason, SignalLine, DEFAULT_WINDOW, MAX_CONTENT_CHARS,
    MAX_HASH_BYTES, SAMPLE_SCHEMA,
};
pub use sha256::{digest as sha256_digest, hex as sha256_hex};

/// Writes bytes to a file that only this user reads.
///
/// The consent file and every sample of the outbox name the machine and its
/// sessions, so both are created with the permission mode 0600 whatever the
/// umask of the command is. A file that already exists keeps the mode it
/// has; creation is the moment the mode is fixed.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

/// One grain of consent.
///
/// Consent is granular by scope: a user decides separately whether the
/// structure of the process tree, the actions themselves, observed content,
/// environment names and the agent identity may travel in a sample. No
/// scope, no sample content beyond the bare reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The process tree: parent links, program names, executable paths and
    /// executable hashes.
    Tree,
    /// What the tree did: command lines, file paths, connection targets, and
    /// the evidence lines of sensed facts.
    Actions,
    /// The content of standard input and of files a process read. This is
    /// the most sensitive scope; it is redacted and capped even when
    /// granted.
    Content,
    /// The names of environment variables a process carried. The values
    /// never travel, whatever this scope says.
    Env,
    /// The agent identity: the detector's name, confidence and signals.
    Identity,
}

impl Scope {
    /// Returns every scope, in the order of the help text.
    pub const ALL: &'static [Scope] = &[
        Scope::Tree,
        Scope::Actions,
        Scope::Content,
        Scope::Env,
        Scope::Identity,
    ];

    /// Reads a scope from a command-line word.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tree" => Some(Scope::Tree),
            "actions" => Some(Scope::Actions),
            "content" => Some(Scope::Content),
            "env" => Some(Scope::Env),
            "identity" => Some(Scope::Identity),
            _ => None,
        }
    }

    /// Returns the name of the scope, as the consent file stores it.
    pub fn label(&self) -> &'static str {
        match self {
            Scope::Tree => "tree",
            Scope::Actions => "actions",
            Scope::Content => "content",
            Scope::Env => "env",
            Scope::Identity => "identity",
        }
    }

    /// Returns one line that says what the scope grants.
    pub fn description(&self) -> &'static str {
        match self {
            Scope::Tree => {
                "the process tree: parent links, program names, executable \
                 paths and executable hashes"
            }
            Scope::Actions => {
                "what the tree did: command lines, file paths, connection \
                 targets, and the evidence lines of sensed facts"
            }
            Scope::Content => {
                "the content of standard input and of read files, redacted \
                 and cut to a safe length — the most sensitive scope"
            }
            Scope::Env => "the names of environment variables; the values never travel",
            Scope::Identity => {
                "the agent identity: which agent the detectors named, with \
                 what confidence and what signals"
            }
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The consent state of one user: which scopes they granted.
///
/// The state lives in one local JSON file (see [`Consent::default_path`]).
/// Nothing else in the firewall reads it: with telemetry off, the product is
/// complete, and no command asks about it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    /// The granted scopes. An empty set is telemetry off.
    #[serde(default)]
    pub scopes: BTreeSet<Scope>,
}

impl Consent {
    /// Returns the state of a user who granted nothing: telemetry off.
    pub fn off() -> Self {
        Self::default()
    }

    /// Returns true when no scope is granted.
    pub fn is_off(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Grants one scope. Idempotent.
    pub fn grant(&mut self, scope: Scope) {
        self.scopes.insert(scope);
    }

    /// Revokes one scope. Idempotent.
    pub fn revoke(&mut self, scope: Scope) {
        self.scopes.remove(&scope);
    }

    /// Revokes every scope: telemetry off again.
    pub fn revoke_all(&mut self) {
        self.scopes.clear();
    }

    /// Returns true when the given scope is granted.
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Returns the granted scopes in the order of the help text.
    pub fn granted(&self) -> Vec<Scope> {
        Scope::ALL
            .iter()
            .copied()
            .filter(|scope| self.scopes.contains(scope))
            .collect()
    }

    /// Returns the default path of the consent file:
    /// `${XDG_CONFIG_HOME:-$HOME/.config}/agent-firewall/telemetry.json`.
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("agent-firewall").join("telemetry.json")
    }

    /// Reads the consent state from a file.
    ///
    /// A file that does not exist is telemetry off, not an error: off is the
    /// default, and most machines never write the file. A scope name that
    /// this version does not know is skipped, so a consent file of a newer
    /// version degrades quietly instead of failing.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::off()),
            Err(error) => return Err(error),
        };
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            scopes: Vec<String>,
        }
        let file: File = serde_json::from_str(&text).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} holds no valid consent state: {error}", path.display()),
            )
        })?;
        let mut scopes = BTreeSet::new();
        for name in file.scopes {
            if let Some(scope) = Scope::parse(&name) {
                scopes.insert(scope);
            }
        }
        Ok(Self { scopes })
    }

    /// Writes the consent state to a file, making the directory first.
    ///
    /// The file is created with the permission mode 0600
    /// ([`write_private`]), because it names the scopes this user granted.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        write_private(path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_is_off_by_default() {
        let consent = Consent::off();
        assert!(consent.is_off());
        for scope in Scope::ALL {
            assert!(!consent.allows(*scope), "{scope} must not be granted");
        }
    }

    #[test]
    fn consent_is_granular_and_revocable() {
        let mut consent = Consent::off();
        consent.grant(Scope::Tree);
        consent.grant(Scope::Actions);
        assert!(consent.allows(Scope::Tree) && consent.allows(Scope::Actions));
        assert!(!consent.allows(Scope::Content), "content stays off");

        consent.revoke(Scope::Actions);
        assert!(!consent.allows(Scope::Actions));
        assert!(consent.allows(Scope::Tree), "revoking one leaves the other");

        consent.grant(Scope::Actions);
        consent.grant(Scope::Actions);
        assert_eq!(consent.granted().len(), 2, "granting twice grants once");

        consent.revoke_all();
        assert!(consent.is_off(), "revoking everything returns to off");
    }

    #[test]
    fn the_consent_file_round_trips() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("nested").join("telemetry.json");

        let mut consent = Consent::off();
        consent.grant(Scope::Actions);
        consent.grant(Scope::Env);
        consent.save(&path).expect("save the consent");

        let back = Consent::load(&path).expect("load the consent");
        assert_eq!(back, consent);
        assert_eq!(back.granted(), vec![Scope::Actions, Scope::Env]);
    }

    #[test]
    fn a_missing_consent_file_is_off_and_not_an_error() {
        let consent = Consent::load(Path::new("/nowhere/agent-firewall/telemetry.json"))
            .expect("a missing file is off");
        assert!(consent.is_off());
    }

    #[test]
    fn an_unknown_scope_name_is_skipped_and_a_broken_file_is_refused() {
        let dir = tempfile::tempdir().expect("temporary directory");

        let future = dir.path().join("future.json");
        std::fs::write(&future, br#"{"scopes":["actions","warp-drive"]}"#).expect("write");
        let consent = Consent::load(&future).expect("the known scope loads");
        assert_eq!(consent.granted(), vec![Scope::Actions]);

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, b"not json").expect("write");
        assert!(Consent::load(&broken).is_err(), "a broken file must refuse");
    }

    #[test]
    fn the_consent_file_is_created_for_its_owner_only() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("telemetry.json");
        let mut consent = Consent::off();
        consent.grant(Scope::Actions);
        consent.save(&path).expect("save the consent");

        let mode = std::fs::metadata(&path).expect("stat").mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the consent state names this user; no other local user may read it"
        );
    }
}
