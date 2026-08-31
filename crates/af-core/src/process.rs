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
    /// Whether the program image of the process needs the dynamic linker.
    ///
    /// The monitor reads this fact from the program file at the exec stop:
    /// `Some(true)` names a program that carries `PT_INTERP`, so it loads the
    /// linker and with it every `LD_PRELOAD` library of its environment;
    /// `Some(false)` names a static program that no preload can reach; `None`
    /// means the monitor could not read the file. Correlation keys on this
    /// fact: a dynamic child of a session that carries the sensor preload
    /// must report, and a static child never can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_link: Option<bool>,
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
    /// A process asks the kernel to send a signal.
    ///
    /// The kernel filter holds this call only when the target is a process
    /// of the firewall itself, so a normal signal of a normal session never
    /// reaches the engine. Both facts of the action are scalars from the
    /// registers, so nothing can race them.
    SignalSend {
        /// Process identifier that receives the signal.
        ///
        /// For a `tgkill` this is the thread group; for a `kill` to a process
        /// group the value is negative.
        target: Pid,
        /// Signal number.
        signal: i32,
    },
    /// The firewall sensed a state of its own visibility that a rule judges.
    ///
    /// The monitor raises these facts, and only these: a descendant that
    /// detached from the session tree, a program that came back after the
    /// firewall killed it, a child whose environment dropped the preload of
    /// the in-process sensor, and a process that was still alive after the
    /// session root ended. Every fact is keyed to what the firewall itself
    /// installed or did, never to the absence of instrumentation on a
    /// foreign process.
    Tamper {
        /// Which shape was sensed.
        kind: TamperKind,
        /// The measured facts behind the sense, one line for the evidence.
        detail: String,
    },
    /// The expected view and the observed view of one session disagree.
    ///
    /// The correlation engine raises these facts by comparing the in-process
    /// sensor's own record with the external view of the monitor. Every kind
    /// is keyed to the sensor instances the firewall itself installed, never
    /// to the absence of instrumentation on a foreign process, which a normal
    /// toolchain produces every day.
    Discrepancy {
        /// Which shape was sensed.
        kind: DiscrepancyKind,
        /// The measured facts behind the sense, one line for the evidence.
        detail: String,
    },
}

/// Which sensed shape a [`Action::Tamper`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    /// A descendant left the session tree, by `setsid` or a detaching parent.
    DetachedDescendant,
    /// A program the firewall killed in this session came back.
    KilledSubtreeReturned,
    /// A child of the session inherited no copy of the sensor preload.
    PreloadStripped,
    /// A process was still alive after the session root ended.
    ///
    /// This is the B.6 liveness fact. It is judged at report level, because
    /// a background job of a normal session has the same shape.
    OutlivedSession,
}

impl TamperKind {
    /// Returns the label that the rule file and the trace use.
    pub fn label(&self) -> &'static str {
        match self {
            TamperKind::DetachedDescendant => "detached_descendant",
            TamperKind::KilledSubtreeReturned => "killed_subtree_returned",
            TamperKind::PreloadStripped => "preload_stripped",
            TamperKind::OutlivedSession => "outlived_session",
        }
    }
}

impl std::fmt::Display for TamperKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Which disagreement a [`Action::Discrepancy`] carries.
///
/// The correlation engine of DIRECTION.md §3.4 compares what the in-process
/// sensor said with what the external view observed, and every kind below is
/// a way for the two views to disagree. The decision log binds how: each kind
/// keys on the sensor instances the firewall itself installed in this
/// session, so a static binary and a raw `syscall()` — which never touch a
/// preload on a foreign process — can never raise one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyKind {
    /// A sensor instance the firewall installed went quiet while its process
    /// lived on.
    ///
    /// The instance proved it talks (a heartbeat), the product view proves
    /// the process lives past the quiet window, and the sensor's last word
    /// was not an exec intent whose image replacement explains the quiet.
    SensorSilentSubtree,
    /// The sensor reported a spawn whose exec the external view never saw.
    ///
    /// In a launch session the exec stop is a kernel guarantee for the whole
    /// tree, so the engine measures this kind and expects zero.
    SpawnReportedUnseen,
    /// The external view saw a spawn that the sensor never reported.
    ///
    /// The fact keys on a child that inherited the session's preload value,
    /// whose program needs the dynamic linker, and whose successor image
    /// never registered a sensor instance. A static child and a child that
    /// stripped the preload from its environment are both quiet: the first
    /// can never report, the second is the tamper fact of M4.
    SpawnSeenUnreported,
    /// The external view held an action that the sensor of the acting
    /// process never reported.
    ///
    /// The fact keys on a process with a registered sensor instance: a file
    /// open or a connection that the kernel filter held crossed the process
    /// without crossing libc, which is the shape of an unhooked or blinded
    /// sensor.
    ActionContradicted,
}

impl DiscrepancyKind {
    /// Returns the label that the rule file and the trace use.
    pub fn label(&self) -> &'static str {
        match self {
            DiscrepancyKind::SensorSilentSubtree => "sensor_silent_subtree",
            DiscrepancyKind::SpawnReportedUnseen => "spawn_reported_unseen",
            DiscrepancyKind::SpawnSeenUnreported => "spawn_seen_unreported",
            DiscrepancyKind::ActionContradicted => "action_contradicted",
        }
    }
}

impl std::fmt::Display for DiscrepancyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
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
            Action::SignalSend { .. } => "signal_send",
            Action::Tamper { .. } => "tamper",
            Action::Discrepancy { .. } => "discrepancy",
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
            Action::SignalSend { target, signal } => {
                format!("signal {signal} to process {target}")
            }
            Action::Tamper { kind, detail } => format!("{kind}: {detail}"),
            Action::Discrepancy { kind, detail } => format!("{kind}: {detail}"),
        }
    }
}
