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
/// | `FileOpen` | keep | drop | drop |
/// | `NetworkConnect` | keep | drop | drop |
/// | `StdinWrite` | keep | drop | drop |
/// | `PolicyDecision` with `allow` | keep | drop | drop |
/// | `PolicyDecision` with another decision | keep | keep | keep |
/// | `ApprovalRequested` | keep | keep | keep |
/// | `ApprovalResolved` | keep | keep | keep |
/// | `MonitorWarning` | keep | keep | drop |
///
/// A `FileOpen` and a `NetworkConnect` that a rule matched still stay in
/// storage, because the policy engine writes a `PolicyDecision` for them.
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
    /// The answer uses one event only. [`crate::TraceWriter`] adds the exec
    /// events that a kept decision names, because one event cannot tell
    /// whether a later rule needs it.
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
