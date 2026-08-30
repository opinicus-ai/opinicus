//! What the policy engine remembers inside one session.
//!
//! A rule that says "a credential file was read, and now data leaves the
//! machine" needs more than one action. This module holds the small store
//! that carries such a fact from one action to the next.
//!
//! Three kinds of knowledge live here:
//!
//! * **Marks.** A rule sets a name when it matches. A later rule asks whether
//!   the name is still live.
//! * **Occurrences.** A rule with a window counts its own hits, so it can ask
//!   for twenty deletes in a minute or for three different credential files.
//! * **A baseline.** The launcher writes named sets of text at session start,
//!   for example the git remotes of the work tree. A rule can ask whether a
//!   value is new.
//!
//! # Determinism
//!
//! Every time value in this module is the time of the observed event. The
//! store never reads a clock. A replay of a trace therefore gives the same
//! answer as the live session, because the trace carries the same times.
//!
//! The engine never writes to the store. It returns a list of
//! [`MemoryEffect`] values, and the caller applies them in event order. The
//! evaluation itself stays free of side effects.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Pid, TimestampNanos};

/// How many nanoseconds are in one second.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// How far a mark reaches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkScope {
    /// The mark holds for the whole session.
    #[default]
    Session,
    /// The mark holds only inside the process subtree that set it.
    Subtree,
}

impl MarkScope {
    /// Returns the label that a rule file uses.
    pub fn label(&self) -> &'static str {
        match self {
            MarkScope::Session => "session",
            MarkScope::Subtree => "subtree",
        }
    }
}

/// One fact that a rule wrote down.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mark {
    /// Time of the action that set the mark.
    ts: TimestampNanos,
    /// Root of the process subtree that set the mark.
    root: Pid,
    /// How far the mark reaches.
    scope: MarkScope,
    /// When the mark stops counting. `None` means for the whole session.
    expires_at: Option<TimestampNanos>,
}

/// One counted hit of a rule that declares a window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Occurrence {
    /// Time of the action.
    ts: TimestampNanos,
    /// The value that makes this hit different from another one.
    ///
    /// The value is `None` when the rule counts hits and not values, and also
    /// when the action carries no value of the wanted kind.
    key: Option<String>,
}

/// What a rule wants the session to remember.
///
/// The policy engine returns these values. It never writes the store itself,
/// so an evaluation has no side effect and a replay stays exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryEffect {
    /// Write a mark down.
    SetMark {
        /// Name of the mark.
        name: String,
        /// How far the mark reaches.
        scope: MarkScope,
        /// Root of the process subtree that set the mark.
        root: Pid,
        /// How long the mark counts, in seconds. `None` means the session.
        ttl_seconds: Option<u64>,
    },
    /// Count one hit of a rule that declares a window.
    NoteOccurrence {
        /// Identifier of the rule that counts.
        rule_id: String,
        /// The value that makes this hit different, when the rule wants one.
        key: Option<String>,
        /// The window of the rule, in seconds. Older hits are dropped.
        window_seconds: u64,
    },
}

/// The memory of one session.
///
/// The store belongs to the caller of the policy engine: the launcher during
/// a live session, and the replay command for a recorded trace. Both apply
/// the same effects in the same order, so both reach the same state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMemory {
    marks: BTreeMap<String, Vec<Mark>>,
    occurrences: BTreeMap<String, Vec<Occurrence>>,
    baseline: BTreeMap<String, BTreeSet<String>>,
}

impl SessionMemory {
    /// Makes an empty memory.
    pub const fn new() -> Self {
        Self {
            marks: BTreeMap::new(),
            occurrences: BTreeMap::new(),
            baseline: BTreeMap::new(),
        }
    }

    /// Makes a memory that already holds the baseline of the session start.
    pub fn with_baseline(baseline: BTreeMap<String, BTreeSet<String>>) -> Self {
        Self {
            marks: BTreeMap::new(),
            occurrences: BTreeMap::new(),
            baseline,
        }
    }

    /// Returns the named sets that the launcher recorded at session start.
    pub fn baseline(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.baseline
    }

    /// Records one effect at the time of the action that produced it.
    ///
    /// This is the only way to change the store. The call also drops the
    /// records that can never count again, so the store stays small in a long
    /// session.
    pub fn apply(&mut self, effect: MemoryEffect, ts: TimestampNanos) {
        match effect {
            MemoryEffect::SetMark {
                name,
                scope,
                root,
                ttl_seconds,
            } => {
                let expires_at = ttl_seconds.map(|seconds| ts.saturating_add(nanos(seconds)));
                let list = self.marks.entry(name).or_default();
                list.retain(|mark| mark.expires_at.is_none_or(|end| end >= ts));
                // One entry for one name in one subtree. A rule that matches a
                // thousand times says the same thing a thousand times, and a
                // store that kept every one of them would grow through the
                // whole session while it answers exactly the same question.
                //
                // The newer entry wins on the time, because the mark is now as
                // fresh as this action. It wins on nothing else: the longer
                // lifetime holds, `None` being the longest of all, and the
                // wider scope holds, because a narrower one would take away
                // what an earlier action already wrote down.
                if let Some(mark) = list.iter_mut().find(|mark| mark.root == root) {
                    mark.ts = mark.ts.max(ts);
                    mark.scope = mark.scope.min(scope);
                    mark.expires_at = match (mark.expires_at, expires_at) {
                        (Some(old), Some(new)) => Some(old.max(new)),
                        _ => None,
                    };
                    return;
                }
                list.push(Mark {
                    ts,
                    root,
                    scope,
                    expires_at,
                });
            }
            MemoryEffect::NoteOccurrence {
                rule_id,
                key,
                window_seconds,
            } => {
                let oldest = ts.saturating_sub(nanos(window_seconds));
                let list = self.occurrences.entry(rule_id).or_default();
                list.retain(|hit| hit.ts >= oldest);
                list.push(Occurrence { ts, key });
            }
        }
    }

    /// Returns true when a live mark with this name is visible.
    ///
    /// `now` is the time of the action that asks. `within_seconds` limits how
    /// old the mark may be. `root` is the root of the subtree that asks, and
    /// it only counts when a scope asks for the subtree.
    ///
    /// A mark that was set for a subtree is invisible outside that subtree. A
    /// reader that asks for `MarkScope::Subtree` also demands the same
    /// subtree, whatever the mark itself declared.
    pub fn has_mark(
        &self,
        name: &str,
        now: TimestampNanos,
        within_seconds: Option<u64>,
        scope: MarkScope,
        root: Pid,
    ) -> bool {
        let Some(list) = self.marks.get(name) else {
            return false;
        };
        let oldest = within_seconds.map(|seconds| now.saturating_sub(nanos(seconds)));
        list.iter().any(|mark| {
            if mark.ts > now {
                return false;
            }
            if let Some(end) = mark.expires_at {
                if end < now {
                    return false;
                }
            }
            if let Some(oldest) = oldest {
                if mark.ts < oldest {
                    return false;
                }
            }
            if mark.scope == MarkScope::Subtree && mark.root != root {
                return false;
            }
            if scope == MarkScope::Subtree && mark.root != root {
                return false;
            }
            true
        })
    }

    /// Counts the hits of a rule inside the trailing window, and adds one.
    ///
    /// The added hit is the action that asks. The engine has not written it
    /// yet, because the caller applies the effects after the evaluation.
    pub fn count_with_current(
        &self,
        rule_id: &str,
        now: TimestampNanos,
        window_seconds: u64,
    ) -> usize {
        self.window(rule_id, now, window_seconds).count() + 1
    }

    /// Counts the different values of a rule inside the window, with this one.
    ///
    /// An action that carries no value adds nothing, so a rule that asks for
    /// three different paths stays quiet while the path is unknown.
    pub fn distinct_with_current(
        &self,
        rule_id: &str,
        now: TimestampNanos,
        window_seconds: u64,
        current: Option<&str>,
    ) -> usize {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for hit in self.window(rule_id, now, window_seconds) {
            if let Some(key) = hit.key.as_deref() {
                seen.insert(key);
            }
        }
        if let Some(key) = current {
            seen.insert(key);
        }
        seen.len()
    }

    /// Says whether a baseline set holds a value.
    ///
    /// The answer is `None` when the session recorded no set with this name.
    /// A rule must then stay quiet, because an unknown set would make every
    /// value look new.
    pub fn baseline_has(&self, set: &str, value: &str) -> Option<bool> {
        self.baseline.get(set).map(|values| values.contains(value))
    }

    /// Returns the hits of a rule that are inside the trailing window.
    fn window(
        &self,
        rule_id: &str,
        now: TimestampNanos,
        window_seconds: u64,
    ) -> impl Iterator<Item = &Occurrence> {
        let oldest = now.saturating_sub(nanos(window_seconds));
        self.occurrences
            .get(rule_id)
            .into_iter()
            .flatten()
            .filter(move |hit| hit.ts >= oldest && hit.ts <= now)
    }
}

/// Converts seconds into nanoseconds and never overflows.
fn nanos(seconds: u64) -> u64 {
    seconds.saturating_mul(NANOS_PER_SECOND)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seconds(value: u64) -> TimestampNanos {
        value * NANOS_PER_SECOND
    }

    fn mark(name: &str, scope: MarkScope, root: Pid, ttl: Option<u64>) -> MemoryEffect {
        MemoryEffect::SetMark {
            name: name.to_string(),
            scope,
            root,
            ttl_seconds: ttl,
        }
    }

    #[test]
    fn a_mark_of_the_session_is_visible_everywhere() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Session, 7, None), seconds(1));
        assert!(memory.has_mark("read", seconds(2), None, MarkScope::Session, 99));
    }

    #[test]
    fn a_mark_of_a_subtree_is_invisible_in_another_subtree() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Subtree, 7, None), seconds(1));
        assert!(memory.has_mark("read", seconds(2), None, MarkScope::Subtree, 7));
        assert!(!memory.has_mark("read", seconds(2), None, MarkScope::Subtree, 8));
        assert!(!memory.has_mark("read", seconds(2), None, MarkScope::Session, 8));
    }

    #[test]
    fn a_mark_stops_counting_after_its_lifetime() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Session, 1, Some(600)), seconds(10));
        assert!(memory.has_mark("read", seconds(600), None, MarkScope::Session, 1));
        assert!(!memory.has_mark("read", seconds(611), None, MarkScope::Session, 1));
    }

    #[test]
    fn a_reader_can_ask_for_a_shorter_time_than_the_lifetime() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Session, 1, Some(600)), seconds(10));
        assert!(memory.has_mark("read", seconds(20), Some(30), MarkScope::Session, 1));
        assert!(!memory.has_mark("read", seconds(100), Some(30), MarkScope::Session, 1));
    }

    #[test]
    fn a_count_holds_only_the_hits_of_the_window() {
        let mut memory = SessionMemory::new();
        for step in 0..5 {
            memory.apply(
                MemoryEffect::NoteOccurrence {
                    rule_id: "fs.burst".to_string(),
                    key: None,
                    window_seconds: 60,
                },
                seconds(step),
            );
        }
        assert_eq!(memory.count_with_current("fs.burst", seconds(5), 60), 6);
        assert_eq!(memory.count_with_current("fs.burst", seconds(300), 60), 1);
    }

    #[test]
    fn a_distinct_count_holds_every_value_one_time() {
        let mut memory = SessionMemory::new();
        for path in ["/a", "/a", "/b"] {
            memory.apply(
                MemoryEffect::NoteOccurrence {
                    rule_id: "secrets.sweep".to_string(),
                    key: Some(path.to_string()),
                    window_seconds: 300,
                },
                seconds(1),
            );
        }
        assert_eq!(
            memory.distinct_with_current("secrets.sweep", seconds(2), 300, Some("/b")),
            2
        );
        assert_eq!(
            memory.distinct_with_current("secrets.sweep", seconds(2), 300, Some("/c")),
            3
        );
        assert_eq!(
            memory.distinct_with_current("secrets.sweep", seconds(2), 300, None),
            2
        );
    }

    #[test]
    fn an_unknown_baseline_set_gives_no_answer() {
        let memory = SessionMemory::new();
        assert_eq!(memory.baseline_has("git_remotes", "origin"), None);
    }

    #[test]
    fn a_baseline_set_answers_for_a_known_and_for_a_new_value() {
        let mut sets = BTreeMap::new();
        sets.insert(
            "git_remotes".to_string(),
            BTreeSet::from(["origin".to_string()]),
        );
        let memory = SessionMemory::with_baseline(sets);
        assert_eq!(memory.baseline_has("git_remotes", "origin"), Some(true));
        assert_eq!(memory.baseline_has("git_remotes", "backup"), Some(false));
    }

    #[test]
    fn one_mark_of_one_subtree_keeps_one_record() {
        let mut memory = SessionMemory::new();
        for step in 0..10_000 {
            memory.apply(
                mark("read", MarkScope::Session, 7, Some(600)),
                seconds(step),
            );
        }
        let kept = memory.marks.get("read").map(Vec::len).unwrap_or(0);
        assert_eq!(
            kept, 1,
            "the same mark of the same subtree is one record, however often a rule writes it"
        );
        // The mark is as fresh as the newest write, so the lifetime counts
        // from there.
        assert!(memory.has_mark("read", seconds(10_500), None, MarkScope::Session, 7));
    }

    #[test]
    fn two_subtrees_keep_their_own_mark() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Subtree, 7, None), seconds(1));
        memory.apply(mark("read", MarkScope::Subtree, 8, None), seconds(2));
        assert_eq!(memory.marks.get("read").map(Vec::len), Some(2));
        assert!(memory.has_mark("read", seconds(3), None, MarkScope::Subtree, 7));
        assert!(memory.has_mark("read", seconds(3), None, MarkScope::Subtree, 8));
    }

    #[test]
    fn a_mark_that_is_written_again_keeps_the_longer_lifetime() {
        let mut memory = SessionMemory::new();
        memory.apply(mark("read", MarkScope::Session, 7, None), seconds(1));
        memory.apply(mark("read", MarkScope::Session, 7, Some(10)), seconds(2));
        assert!(
            memory.has_mark("read", seconds(1000), None, MarkScope::Session, 7),
            "a mark of the whole session must not lose its lifetime to a shorter one"
        );
    }

    #[test]
    fn the_store_drops_records_that_can_never_count_again() {
        let mut memory = SessionMemory::new();
        for step in 0..100 {
            memory.apply(
                MemoryEffect::NoteOccurrence {
                    rule_id: "fs.burst".to_string(),
                    key: None,
                    window_seconds: 10,
                },
                seconds(step),
            );
        }
        let kept = memory
            .occurrences
            .get("fs.burst")
            .map(Vec::len)
            .unwrap_or(0);
        assert!(kept <= 11, "the window keeps only its own seconds: {kept}");
    }
}
