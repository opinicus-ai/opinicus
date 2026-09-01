//! Which events go to storage.

use std::str::FromStr;

use af_core::{Decision, Error, Event, EventKind};
use serde::{Deserialize, Serialize};

/// Which events go to storage.
///
/// The firewall must not keep every low-level event of every session. Storage
/// therefore depends on risk: a blocked action keeps full evidence, and
/// normal development activity goes away.
///
/// | Event | `All` | `Balanced` | `EvidenceOnly` |
/// | --- | --- | --- | --- |
/// | `SessionStart` | keep | keep | keep |
/// | `SessionEnd` | keep | keep | keep |
/// | `ProcessFork` | keep | keep | drop |
/// | `ProcessExec` | keep | keep | only when a kept decision names the process |
/// | `ProcessExit` | keep | keep | drop |
/// | `ProcessUnlinked` | keep | keep | keep |
/// | `FileOpen` | keep | only when a rule matched it | drop |
/// | `NetworkConnect` | keep | only when a rule matched it | drop |
/// | `StdinWrite` | keep | drop | drop |
/// | `PolicyDecision` with `allow` | keep | drop | drop |
/// | `PolicyDecision` with another decision | keep | keep | keep |
/// | `ApprovalRequested` | keep | keep | keep |
/// | `ApprovalResolved` | keep | keep | keep |
/// | `MonitorWarning` | keep | keep | drop |
///
/// # A file open that a rule matched
///
/// [`Retention::Balanced`] keeps a `FileOpen` and a `NetworkConnect` when at
/// least **one rule matched it**, and it drops the rest. The firewall emits
/// the action event and the `PolicyDecision` of that action directly after
/// it, so [`crate::TraceWriter`] holds such an event back for exactly one
/// event and writes it when the decision that follows names a rule. A match
/// of the level `info` counts: the mark of a credential read is such a match,
/// and the session memory of the replay needs it.
///
/// An event that no rule matched stays dropped. Its verdict came from zero
/// rules, so a replay of the trace cannot lose a verdict by not seeing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    /// Keep every event. Use it during research.
    All,
    /// Keep evidence and process activity, drop noisy events that no rule
    /// matched.
    Balanced,
    /// Keep only the events that explain a decision.
    EvidenceOnly,
}

impl Retention {
    /// Returns true when this event alone belongs in storage.
    ///
    /// The answer uses one event only. [`crate::TraceWriter`] adds the events
    /// that a kept decision needs, because one event cannot tell whether a
    /// later rule needs it: the exec events that a kept decision names under
    /// [`Retention::EvidenceOnly`], and the held action of a decision with a
    /// match under [`Retention::Balanced`].
    pub fn should_keep(&self, event: &Event) -> bool {
        match self {
            Retention::All => true,
            Retention::Balanced => balanced_keeps(&event.kind),
            Retention::EvidenceOnly => event.kind.is_evidence(),
        }
    }

    /// Returns a short label for the user interface and for configuration.
    pub fn label(&self) -> &'static str {
        match self {
            Retention::All => "all",
            Retention::Balanced => "balanced",
            Retention::EvidenceOnly => "evidence-only",
        }
    }

    /// Returns every level, from the widest to the narrowest.
    pub fn all_levels() -> [Retention; 3] {
        [Retention::All, Retention::Balanced, Retention::EvidenceOnly]
    }
}

impl Default for Retention {
    /// Returns [`Retention::Balanced`], which fits a normal session.
    fn default() -> Self {
        Retention::Balanced
    }
}

impl std::fmt::Display for Retention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Retention {
    type Err = Error;

    /// Reads a level from a command-line value or a configuration file.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Retention::All),
            "balanced" => Ok(Retention::Balanced),
            "evidence-only" | "evidence_only" | "evidenceonly" | "evidence" => {
                Ok(Retention::EvidenceOnly)
            }
            other => Err(Error::other(format!(
                "unknown retention level: {other}; use all, balanced or evidence-only"
            ))),
        }
    }
}

/// Returns true when [`Retention::Balanced`] keeps this event.
fn balanced_keeps(kind: &EventKind) -> bool {
    if kind.is_evidence() {
        return true;
    }
    matches!(
        kind,
        EventKind::ProcessFork { .. }
            | EventKind::ProcessExec { .. }
            | EventKind::ProcessExit { .. }
            | EventKind::MonitorWarning { .. }
    )
}

/// Returns the processes that a kept event names.
///
/// A decision names the process that acts and every process of its ancestry.
/// [`Retention::EvidenceOnly`] keeps the exec events of these processes, so
/// that a replay of the trace still draws the chain.
pub(crate) fn named_processes(event: &Event) -> Vec<af_core::Pid> {
    let mut pids = vec![event.pid];
    match &event.kind {
        EventKind::PolicyDecision {
            verdict, ancestry, ..
        } => {
            if verdict.decision == Decision::Allow {
                return Vec::new();
            }
            pids.extend(ancestry.iter().map(|process| process.pid));
        }
        EventKind::ApprovalRequested { .. } | EventKind::ApprovalResolved { .. } => {}
        _ => return Vec::new(),
    }
    pids
}

/// Returns true when this event is the action that [`Retention::Balanced`]
/// holds back until it knows whether a rule matched it.
pub(crate) fn is_held_action(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::FileOpen { .. } | EventKind::NetworkConnect { .. } | EventKind::IoUring { .. }
    )
}

/// Returns true when `decision` is the verdict of the held action `held`, and
/// at least one rule matched.
///
/// The firewall emits the action first and the decision of that action
/// directly after it, both for the same process. A decision with no match
/// leaves the action out of storage, because such a verdict comes from zero
/// rules and a replay cannot lose it.
pub(crate) fn decides_about(held: &Event, decision: &Event) -> bool {
    let EventKind::PolicyDecision {
        action, verdict, ..
    } = &decision.kind
    else {
        return false;
    };
    if decision.pid != held.pid || verdict.matches.is_empty() {
        return false;
    }
    match (&held.kind, &**action) {
        (
            EventKind::FileOpen { path, write },
            af_core::Action::FileOpen {
                path: other_path,
                write: other_write,
            },
        ) => path == other_path && write == other_write,
        (
            EventKind::NetworkConnect { addr, port, .. },
            af_core::Action::NetworkConnect {
                addr: other_addr,
                port: other_port,
                ..
            },
        ) => addr == other_addr && port == other_port,
        (EventKind::IoUring { call }, af_core::Action::IoUring { call: other }) => call == other,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_read_back_from_text() {
        for level in Retention::all_levels() {
            let text = level.label();
            assert_eq!(Retention::from_str(text).expect("parse"), level);
        }
        assert_eq!(
            Retention::from_str("EVIDENCE_ONLY").expect("parse"),
            Retention::EvidenceOnly
        );
        assert!(Retention::from_str("none").is_err());
    }
}
