//! Process facts and the actions that a policy can evaluate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Pid;

/// Stable identity of one process.
///
/// Linux reuses process identifiers. The start time of the process makes the
/// identifier unique for the lifetime of one boot, so the provenance graph
/// keys on this pair instead of the raw identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessKey {
    /// Process identifier.
    pub pid: Pid,
    /// Start time of the process in clock ticks after boot.
    ///
    /// The value is `0` when the monitor cannot read it.
    #[serde(default)]
    pub start_ticks: u64,
}

impl ProcessKey {
    /// Makes a key from a process identifier and a start time.
    pub fn new(pid: Pid, start_ticks: u64) -> Self {
        Self { pid, start_ticks }
    }

    /// Makes a key when only the process identifier is known.
    pub fn from_pid(pid: Pid) -> Self {
        Self {
            pid,
            start_ticks: 0,
        }
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pid)
    }
}

/// Everything the monitor knows about one process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process identifier.
    pub pid: Pid,
    /// Identifier of the parent process, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<Pid>,
    /// Start time of the process in clock ticks after boot.
    #[serde(default)]
    pub start_ticks: u64,
    /// Full path of the running program, when the monitor can read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Program name without directories, for example `psql`.
    #[serde(default)]
    pub comm: String,
    /// Command line of the process.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Working directory of the process, when the monitor can read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Selected environment variables.
    ///
    /// The monitor keeps only names that a policy needs. It never keeps a
    /// value that looks like a secret.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Session identifier of the process, when the monitor could read it.
    ///
    /// The value comes from `/proc/<pid>/stat`. Every process of a session
    /// shares the identifier until one of them calls `setsid`, so a value
    /// that differs from the session root says that the process — or a
    /// process above it — detached from the session. That is the B.6
    /// liveness fact, not an accusation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<Pid>,
}

impl ProcessInfo {
    /// Makes a minimal record for a process that is only known by identifier.
    pub fn from_pid(pid: Pid) -> Self {
        Self {
            pid,
            ..Default::default()
        }
    }

    /// Returns the stable key of this process.
    pub fn key(&self) -> ProcessKey {
        ProcessKey::new(self.pid, self.start_ticks)
    }

    /// Returns the program name without directories.
    ///
    /// The value comes from the executable path when it is known, and from
    /// `comm` or the first command-line word when it is not.
    pub fn program_name(&self) -> &str {
        if let Some(exe) = self.exe.as_deref() {
            if let Some(name) = exe.rsplit('/').next() {
                if !name.is_empty() {
                    return name;
                }
            }
        }
        if !self.comm.is_empty() {
            return &self.comm;
        }
        self.argv
            .first()
            .map(|a| a.rsplit('/').next().unwrap_or(a.as_str()))
            .unwrap_or("")
    }

    /// Returns the command line as one line of text, for display only.
    pub fn command_line(&self) -> String {
        if self.argv.is_empty() {
            return self.program_name().to_string();
        }
        self.argv.join(" ")
    }
}

/// Where an observed piece of input came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSource {
    /// The command line of the process.
    Argv,
    /// The standard input stream of the process.
    Stdin,
    /// A file that the process reads, for example an SQL script.
    File,
    /// An environment variable.
    Environment,
}

/// One action that the policy engine can evaluate.
///
/// The monitor makes an action from one or more normalized events. The
/// action holds all facts a rule needs, so a rule never reads the operating
/// system directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// A process is about to run a program.
    Exec {
        /// Full path of the program, when known.
        exe: Option<String>,
        /// Program name without directories.
        program: String,
        /// Command line of the new program.
        argv: Vec<String>,
        /// Working directory of the process, when known.
        cwd: Option<String>,
        /// Selected environment variables of the process.
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// A process opens a file.
    FileOpen {
        /// Path of the file.
        path: String,
        /// True when the process opens the file for writing.
        write: bool,
    },
    /// A process opens a network connection.
    NetworkConnect {
        /// Host name, when known.
        host: Option<String>,
        /// Address of the remote end.
        addr: String,
        /// Port of the remote end.
        port: u16,
    },
    /// Content that a process reads or receives.
    Input {
        /// Where the content came from.
        source: InputSource,
        /// The content itself, cut to a safe length.
        data: String,
    },
}

impl Action {
    /// Returns the program name for an [`Action::Exec`], and `None` otherwise.
    pub fn program(&self) -> Option<&str> {
        match self {
            Action::Exec { program, .. } => Some(program.as_str()),
            _ => None,
        }
    }

    /// Returns a short label of the action kind, for display and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Exec { .. } => "exec",
            Action::FileOpen { .. } => "file_open",
            Action::NetworkConnect { .. } => "network_connect",
            Action::Input { .. } => "input",
        }
    }

    /// Returns a one-line description of the action for the user.
    pub fn summary(&self) -> String {
        match self {
            Action::Exec { argv, program, .. } => {
                if argv.is_empty() {
                    program.clone()
                } else {
                    argv.join(" ")
                }
            }
            Action::FileOpen { path, write } => {
                let mode = if *write { "write" } else { "read" };
                format!("open {path} for {mode}")
            }
            Action::NetworkConnect { host, addr, port } => match host {
                Some(h) => format!("connect to {h} ({addr}:{port})"),
                None => format!("connect to {addr}:{port}"),
            },
            Action::Input { source, data } => {
                format!(
                    "{source:?} content: {}",
                    crate::display::truncate(data, 160)
                )
            }
        }
    }
}
