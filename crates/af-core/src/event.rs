//! The normalized event schema.
//!
//! Every platform collector must convert its own events into an [`Event`].
//! The rest of the system reads only this format, so a recorded trace can be
//! replayed on any machine.

use serde::{Deserialize, Serialize};

use crate::{
    decision::Verdict,
    identity::{AgentTag, SessionDetach},
    process::{Action, DiscrepancyKind, IoUringCall, ProcessInfo, TamperKind},
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

/// One path prefix that the kernel floor denies, with the rule it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelDeniedPath {
    /// The absolute prefix. An open whose path begins with it fails with
    /// `EACCES`.
    pub prefix: String,
    /// The rule class the kernel enforces on this prefix.
    pub rule: String,
}

/// One normalized event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Position of the event in the session. The first event has number 1.
    pub seq: u64,
    /// Time of the event, in nanoseconds after the Unix epoch.
    pub ts: TimestampNanos,
    /// Session that produced the event.
    pub session_id: SessionId,
    /// Process that the event belongs to.
    pub pid: Pid,
    /// Agent identity of the process, when the session tagged one.
    ///
    /// The tag is `None` while the session carries no identified agent, which
    /// is the normal case of a plain shell. The tag says that the detectors
    /// identified the session root as an agent, and that the identity
    /// propagated to this process through the provenance graph. A process the
    /// graph flagged as unlinked keeps the tag and names the flag in
    /// [`AgentTag::link`] — unlinked, never foreign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentTag>,
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
            agent: None,
            kind,
        }
    }

    /// Returns a short label of the event kind.
    pub fn kind_label(&self) -> &'static str {
        self.kind.label()
    }
}

/// All event kinds of the normalized schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        /// Session identifier of the process at its end, when the monitor
        /// could read it.
        ///
        /// A daemon that calls `setsid` and never runs another program
        /// carries no exec event, so its detachment becomes visible only
        /// here. The graph compares this value with the session root's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sid: Option<Pid>,
    },
    /// The provenance graph flagged a process as detached from the tree of
    /// the session root.
    ///
    /// This is the B.6 liveness fact: the process called `setsid` (or a
    /// process above it did), so it can outlive the session and its later
    /// actions can arrive with no link back. The trace stop itself keeps
    /// following the process — a launch session cannot escape its tracer —
    /// which is exactly why the flag reports detachment and never claims the
    /// process went unseen.
    ///
    /// The flag never says that the process is foreign. The process keeps its
    /// recorded ancestry and its agent identity; an event of an unlinked
    /// process carries the agent tag with [`crate::AgentLink::Unlinked`].
    ProcessUnlinked {
        /// Facts about the process at the moment the graph flagged it.
        process: Box<ProcessInfo>,
        /// The measured session identifiers that differ.
        detach: SessionDetach,
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
    /// A process asked the kernel to send a signal to a process of the
    /// firewall.
    ///
    /// The kernel filter holds this call before it happens, and only when
    /// the target is the monitor. The call has not run when this event is
    /// written, so a refusal stops the signal completely.
    SignalSend {
        /// Process identifier that receives the signal.
        target: Pid,
        /// Signal number.
        signal: i32,
    },
    /// A process asked the kernel for an `io_uring` instance, or submitted
    /// work to one.
    ///
    /// The kernel filter holds both calls before they happen. The event is
    /// the evidence that the ring road reached a boundary at all: without
    /// the hold, a ring performs its operations inside the kernel and no
    /// event of any kind can appear.
    IoUring {
        /// Which of the two `io_uring` calls the process made.
        call: IoUringCall,
    },
    /// The firewall sensed a state of its own visibility that a rule judges.
    ///
    /// The event is evidence, whatever the rules say about it: a trace holds
    /// the attempt also in a session that carries no tamper rule.
    Tamper {
        /// Which shape was sensed.
        kind: TamperKind,
        /// The measured facts behind the sense, one line.
        detail: String,
    },
    /// The expected view and the observed view of the session disagree.
    ///
    /// The correlation engine raises the fact by comparing the record of the
    /// in-process sensor with the external view of the monitor. The event is
    /// evidence, whatever the rules say about it, and every kind keys on the
    /// sensor instances the firewall itself installed.
    Discrepancy {
        /// Which disagreement was sensed.
        kind: DiscrepancyKind,
        /// The measured facts behind the sense, one line.
        detail: String,
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
    /// The firewall suspended the whole session tree and waits for a ruling.
    ///
    /// A quarantine is the most expensive question there is, so only a rule
    /// that names `quarantine: true` starts one. The event names the rule,
    /// the evidence line names what was sensed, and the ruling follows as an
    /// ordinary approval pair.
    QuarantineStarted {
        /// Identifier of the rule that holds the session.
        rule: String,
        /// The evidence the user rules on, one line.
        evidence: String,
    },
    /// The ruling over a quarantined tree.
    ///
    /// The outcome is the answer of the user: allow once, an exception for
    /// the session, or the end of the tree. After it the tree runs again, or
    /// is gone.
    QuarantineResolved {
        /// Identifier of the rule that held the session.
        rule: String,
        /// The ruling.
        outcome: ApprovalOutcome,
    },
    /// The kernel floor of this session became active.
    ///
    /// The child enacted a Landlock ruleset before its first program ran, so
    /// the rule classes the event names are enforced by the kernel for the
    /// rest of the session: their actions fail with `EACCES`, no approval can
    /// allow them, and the session never needs to ask them.
    KernelFloor {
        /// The rule classes the kernel enforces for this session, whose
        /// questions the session no longer asks.
        rules: Vec<String>,
        /// The absolute path prefixes the kernel denies on a file open, each
        /// with the rule class it answers. The prefixes are facts of the
        /// enacted ruleset, which no approval can relax.
        #[serde(default)]
        denied: Vec<KernelDeniedPath>,
    },
    /// The kernel refused an action that the firewall had let continue.
    ///
    /// The floor denied the open, so the call failed with `EACCES` and the
    /// program saw an ordinary permission error. The event names the rule
    /// class the kernel enforced, because a bare `EACCES` names nobody — the
    /// user would blame the file mode or the firewall for something a rule
    /// class chose on purpose.
    KernelDenied {
        /// The rule whose class the kernel enforced, when one maps to the
        /// denied path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        /// The path that the program asked for.
        path: String,
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
            EventKind::ProcessUnlinked { .. } => "process_unlinked",
            EventKind::FileOpen { .. } => "file_open",
            EventKind::NetworkConnect { .. } => "network_connect",
            EventKind::SignalSend { .. } => "signal_send",
            EventKind::IoUring { .. } => "io_uring",
            EventKind::Tamper { .. } => "tamper",
            EventKind::Discrepancy { .. } => "discrepancy",
            EventKind::FileRead { .. } => "file_read",
            EventKind::FileDelete { .. } => "file_delete",
            EventKind::FileRename { .. } => "file_rename",
            EventKind::LibraryLoad { .. } => "library_load",
            EventKind::EnvChange { .. } => "env_change",
            EventKind::StdinWrite { .. } => "stdin_write",
            EventKind::KernelFloor { .. } => "kernel_floor",
            EventKind::KernelDenied { .. } => "kernel_denied",
            EventKind::PolicyDecision { .. } => "policy_decision",
            EventKind::ApprovalRequested { .. } => "approval_requested",
            EventKind::ApprovalResolved { .. } => "approval_resolved",
            EventKind::QuarantineStarted { .. } => "quarantine_started",
            EventKind::QuarantineResolved { .. } => "quarantine_resolved",
            EventKind::MonitorWarning { .. } => "monitor_warning",
            EventKind::SessionEnd { .. } => "session_end",
        }
    }

    /// Returns true when the event must always stay in storage.
    ///
    /// Retention depends on risk. A decision, a question, an answer, the
    /// start and end of a session, and a process that detached from the tree
    /// are always evidence.
    pub fn is_evidence(&self) -> bool {
        matches!(
            self,
            EventKind::SessionStart { .. }
                | EventKind::SessionEnd { .. }
                | EventKind::ApprovalRequested { .. }
                | EventKind::ApprovalResolved { .. }
                | EventKind::QuarantineStarted { .. }
                | EventKind::QuarantineResolved { .. }
                | EventKind::ProcessUnlinked { .. }
                | EventKind::SignalSend { .. }
                | EventKind::Tamper { .. }
                | EventKind::Discrepancy { .. }
                | EventKind::KernelFloor { .. }
                | EventKind::KernelDenied { .. }
        ) || matches!(
            self,
            EventKind::PolicyDecision { verdict, .. } if verdict.decision != crate::Decision::Allow
        )
    }

    /// Returns true when the recorder must write this event through to the
    /// kernel before it takes the next one.
    ///
    /// Evidence is one half of the rule. The other half is every event that
    /// says who ran when: a monitor that an attack kills takes no cleanup
    /// path with it, so the events that name the processes of the session —
    /// the fork, the exec, the end — must reach the file as they happen, or
    /// the attack erases its own record. That failure is measured in
    /// `research/bypass/FINDINGS.md`: the trace of a killed monitor survived
    /// with exactly one line.
    ///
    /// File opens, connections and input stay buffered: a session makes
    /// thousands of them, and a write per event would tax every session for
    /// a fact that the process events already carry.
    pub fn is_durable(&self) -> bool {
        self.is_evidence()
            || matches!(
                self,
                EventKind::ProcessFork { .. }
                    | EventKind::ProcessExec { .. }
                    | EventKind::ProcessExit { .. }
                    | EventKind::MonitorWarning { .. }
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
    fn discrepancy_events_round_trip_through_json() {
        // Every disagreement the correlation engine can raise, as the trace
        // carries it. Evidence is the point: retention keeps the event in
        // every mode.
        for kind in [
            DiscrepancyKind::SensorSilentSubtree,
            DiscrepancyKind::SpawnReportedUnseen,
            DiscrepancyKind::SpawnSeenUnreported,
            DiscrepancyKind::ActionContradicted,
        ] {
            let event = Event::new(
                SessionId::from("afw-correlate"),
                42,
                EventKind::Discrepancy {
                    kind,
                    detail: format!("{kind}: measured evidence"),
                },
            );
            assert!(event.kind.is_evidence());
            let text = serde_json::to_string(&event).expect("encode");
            assert!(text.contains("\"type\":\"discrepancy\""));
            let back: Event = serde_json::from_str(&text).expect("decode");
            assert_eq!(back, event);
        }
    }

    #[test]
    fn the_dynamic_link_fact_travels_with_the_process_and_stays_absent_when_unknown() {
        let mut process = ProcessInfo {
            pid: 7,
            exe: Some("/usr/bin/psql".to_string()),
            comm: "psql".to_string(),
            ..Default::default()
        };
        process.dynamic_link = Some(true);
        let event = Event::new(
            SessionId::from("afw-link"),
            7,
            EventKind::ProcessExec {
                process: Box::new(process),
            },
        );
        let text = serde_json::to_string(&event).expect("encode");
        assert!(text.contains("\"dynamic_link\":true"));
        let back: Event = serde_json::from_str(&text).expect("decode");
        assert_eq!(back, event);

        // A process the monitor could not read carries no guess, and an
        // older trace reads back with the fact absent.
        let plain = Event::new(
            SessionId::from("afw-link"),
            7,
            EventKind::ProcessExec {
                process: Box::new(ProcessInfo::from_pid(7)),
            },
        );
        let text = serde_json::to_string(&plain).expect("encode");
        assert!(!text.contains("dynamic_link"));
        let back: Event = serde_json::from_str(&text).expect("decode");
        assert_eq!(back.kind, plain.kind);
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

    #[test]
    fn an_agent_tag_and_an_unlink_flag_round_trip_through_json() {
        let mut event = Event::new(
            SessionId::from("afw-identity"),
            42,
            EventKind::ProcessUnlinked {
                process: Box::new(ProcessInfo::from_pid(42)),
                detach: crate::SessionDetach {
                    sid: 4752,
                    root_sid: 4701,
                },
            },
        );
        event.agent = Some(crate::AgentTag {
            name: "claude-code".to_string(),
            confidence: 0.95,
            link: crate::AgentLink::Unlinked,
        });
        let text = serde_json::to_string(&event).expect("encode");
        assert!(text.contains("\"type\":\"process_unlinked\""));
        assert!(text.contains("\"sid\":4752"));
        assert!(text.contains("\"link\":\"unlinked\""));
        let back: Event = serde_json::from_str(&text).expect("decode");
        assert_eq!(back, event);
        assert!(back.kind.is_evidence());
    }

    #[test]
    fn an_event_without_a_tag_stays_without_one_in_the_trace() {
        // A normal session carries no tag, and the trace must not carry an
        // empty field for it.
        let event = Event::new(
            SessionId::from("afw-plain"),
            7,
            EventKind::FileOpen {
                path: "/tmp/x".to_string(),
                write: false,
            },
        );
        let text = serde_json::to_string(&event).expect("encode");
        assert!(!text.contains("\"agent\""));
        let back: Event = serde_json::from_str(&text).expect("decode");
        assert_eq!(back.agent, None);
    }
}
