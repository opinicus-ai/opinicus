//! The normalized event schema.
//!
//! Every platform collector must convert its own events into an [`Event`].
//! The rest of the system reads only this format, so a recorded trace can be
//! replayed on any machine.

use serde::{Deserialize, Serialize};

use crate::{
    decision::Verdict,
    process::{Action, ProcessInfo},
    session::{SessionId, SessionMeta},
    traits::ApprovalOutcome,
    Pid, TimestampNanos,
};

/// Which stream carried a piece of observed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputStream {
    /// Standard input of the process.
    Stdin,
    /// Standard output of the process.
    Stdout,
    /// Standard error of the process.
    Stderr,
    /// A pipe between two monitored processes.
    Pipe,
}

/// Something the monitor can or cannot observe on this machine.
///
/// The launcher reports the capabilities once, so that the user knows how
/// complete the protection is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorCapability {
    /// Name of the capability, for example `exec_interception`.
    pub name: String,
    /// True when the capability is available.
    pub available: bool,
    /// Why the capability is not available, when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl MonitorCapability {
    /// Makes a capability record that is available.
    pub fn available(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            available: true,
            detail: None,
        }
    }

    /// Makes a capability record that is not available.
    pub fn missing(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            available: false,
            detail: Some(detail.into()),
        }
    }
}

/// One normalized event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Position of the event in the session. The first event has number 1.
    pub seq: u64,
    /// Time of the event, in nanoseconds after the Unix epoch.
    pub ts: TimestampNanos,
    /// Session that produced the event.
    pub session_id: SessionId,
    /// Process that the event belongs to.
    pub pid: Pid,
    /// The event itself.
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    /// Makes an event. The recorder sets the sequence number.
    pub fn new(session_id: SessionId, pid: Pid, kind: EventKind) -> Self {
        Self {
            seq: 0,
            ts: crate::now_nanos(),
            session_id,
            pid,
            kind,
        }
    }

    /// Returns a short label of the event kind.
    pub fn kind_label(&self) -> &'static str {
        self.kind.label()
    }
}

/// All event kinds of the normalized schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// The launcher started a session.
    SessionStart {
        /// Metadata of the session.
        meta: Box<SessionMeta>,
        /// What the monitor can observe on this machine.
        #[serde(default)]
        capabilities: Vec<MonitorCapability>,
    },
    /// A process created a child process.
    ProcessFork {
        /// Identifier of the child process.
        child_pid: Pid,
        /// True when the child is a thread of the same program.
        #[serde(default)]
        is_thread: bool,
    },
    /// A process replaced its program image.
    ProcessExec {
        /// Facts about the process after the change.
        process: Box<ProcessInfo>,
    },
    /// A process ended.
    ProcessExit {
        /// Exit code of the process, when it ended normally.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        /// Signal that ended the process, when a signal ended it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    /// A process opened a file.
    FileOpen {
        /// Path of the file.
        path: String,
        /// True when the process opened the file for writing.
        write: bool,
    },
    /// A process opened a network connection.
    NetworkConnect {
        /// Address of the remote end.
        addr: String,
        /// Port of the remote end.
        port: u16,
        /// Host name, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// A process read the content of a small file into memory.
    ///
    /// The in-process sensor reports this. The shipped monitor does not
    /// produce it. The content is cut to a small length.
    FileRead {
        /// Path of the file.
        path: String,
        /// The content that the process read, cut to a safe length.
        data: String,
    },
    /// A process removed a file or a directory.
    ///
    /// The in-process sensor reports this. The shipped monitor holds no
    /// delete, so no product rule can act on it yet.
    FileDelete {
        /// Path of the file.
        path: String,
    },
    /// A process renamed or moved a file.
    ///
    /// The in-process sensor reports this. The shipped monitor holds no
    /// rename, so no product rule can act on it yet.
    FileRename {
        /// Path before the change.
        from: String,
        /// Path after the change.
        to: String,
    },
    /// A process loaded a shared object at run time.
    ///
    /// The in-process sensor reports this.
    LibraryLoad {
        /// Path of the shared object.
        path: String,
    },
    /// A process changed a variable of its own environment.
    ///
    /// The in-process sensor reports this.
    EnvChange {
        /// Name of the variable.
        name: String,
        /// New value of the variable, or `None` when the process removed it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
    },
    /// The monitor observed content on a stream of a process.
    StdinWrite {
        /// Which stream carried the content.
        stream: InputStream,
        /// The content, cut to a safe length.
        data: String,
    },
    /// The policy engine evaluated an action.
    PolicyDecision {
        /// The action that the engine evaluated.
        action: Box<Action>,
        /// The result of the evaluation.
        verdict: Box<Verdict>,
        /// Ancestry of the process, nearest parent first.
        #[serde(default)]
        ancestry: Vec<ProcessInfo>,
    },
    /// The firewall asked the user for a decision.
    ApprovalRequested {
        /// The action that waits for a decision.
        action: Box<Action>,
        /// Identifier of the rule that caused the question.
        rule_id: String,
    },
    /// The user answered a question.
    ApprovalResolved {
        /// Identifier of the rule that caused the question.
        rule_id: String,
        /// The answer of the user.
        outcome: ApprovalOutcome,
        /// How long the user needed to answer, in milliseconds.
        #[serde(default)]
        waited_ms: u64,
    },
    /// The monitor could not observe something.
    MonitorWarning {
        /// What went wrong.
        message: String,
    },
    /// The session ended.
    SessionEnd {
        /// Exit code of the root process.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// How many processes the session created.
        #[serde(default)]
        process_count: usize,
    },
}

impl EventKind {
    /// Returns a short label of the event kind.
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::SessionStart { .. } => "session_start",
            EventKind::ProcessFork { .. } => "process_fork",
            EventKind::ProcessExec { .. } => "process_exec",
            EventKind::ProcessExit { .. } => "process_exit",
            EventKind::FileOpen { .. } => "file_open",
            EventKind::NetworkConnect { .. } => "network_connect",
            EventKind::FileRead { .. } => "file_read",
            EventKind::FileDelete { .. } => "file_delete",
            EventKind::FileRename { .. } => "file_rename",
            EventKind::LibraryLoad { .. } => "library_load",
            EventKind::EnvChange { .. } => "env_change",
            EventKind::StdinWrite { .. } => "stdin_write",
            EventKind::PolicyDecision { .. } => "policy_decision",
            EventKind::ApprovalRequested { .. } => "approval_requested",
            EventKind::ApprovalResolved { .. } => "approval_resolved",
            EventKind::MonitorWarning { .. } => "monitor_warning",
            EventKind::SessionEnd { .. } => "session_end",
        }
    }

    /// Returns true when the event must always stay in storage.
    ///
    /// Retention depends on risk. A decision, a question, an answer and the
    /// start and end of a session are always evidence.
    pub fn is_evidence(&self) -> bool {
        matches!(
            self,
            EventKind::SessionStart { .. }
                | EventKind::SessionEnd { .. }
                | EventKind::ApprovalRequested { .. }
                | EventKind::ApprovalResolved { .. }
        ) || matches!(
            self,
            EventKind::PolicyDecision { verdict, .. } if verdict.decision != crate::Decision::Allow
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trips_through_json() {
        let event = Event::new(
            SessionId::from("afw-test"),
            42,
            EventKind::ProcessExec {
                process: Box::new(ProcessInfo {
                    pid: 42,
                    ppid: Some(41),
                    exe: Some("/usr/bin/psql".to_string()),
                    comm: "psql".to_string(),
                    argv: vec!["psql".to_string(), "-c".to_string()],
                    ..Default::default()
                }),
            },
        );
        let text = serde_json::to_string(&event).expect("encode");
        assert!(text.contains("\"type\":\"process_exec\""));
        let back: Event = serde_json::from_str(&text).expect("decode");
        assert_eq!(back, event);
    }

    #[test]
    fn allow_decisions_are_not_evidence() {
        let allow = EventKind::PolicyDecision {
            action: Box::new(Action::FileOpen {
                path: "/tmp/x".to_string(),
                write: false,
            }),
            verdict: Box::new(Verdict::allow()),
            ancestry: Vec::new(),
        };
        assert!(!allow.is_evidence());
    }

    #[test]
    fn sensor_events_round_trip_through_json() {
        // The kinds that only the in-process sensor produces today. They are
        // part of the schema, so a sensor trace reads back like any trace.
        let cases = vec![
            EventKind::FileRead {
                path: "/tmp/drop.py".to_string(),
                data: "DROP DATABASE customer_prod".to_string(),
            },
            EventKind::FileDelete {
                path: "/tmp/victim/f".to_string(),
            },
            EventKind::FileRename {
                from: "/tmp/victim".to_string(),
                to: "/tmp/moved".to_string(),
            },
            EventKind::LibraryLoad {
                path: "/usr/lib64/libcurl.so.4".to_string(),
            },
            EventKind::EnvChange {
                name: "LD_PRELOAD".to_string(),
                value: None,
            },
        ];
        for kind in cases {
            let event = Event::new(SessionId::from("afw-sensor"), 7, kind);
            let text = serde_json::to_string(&event).expect("encode");
            let back: Event = serde_json::from_str(&text).expect("decode");
            assert_eq!(back, event);
            assert!(text.contains(&format!("\"type\":\"{}\"", event.kind.label())));
        }
    }
}
