//! The provenance of the path facts that a rule matches on.
//!
//! A rule can ask about two kinds of path, and the difference is a
//! measurement, not a style choice (`docs/DETECTION-RESEARCH.md` section 2,
//! `research/spikes/seccomp-unotify/FINDINGS.md`):
//!
//! * The path of a held file open is **read out of the memory of the judged
//!   program** at the `seccomp` stop. A second thread of that program can
//!   rewrite the buffer before the kernel reads it again: measured, the path
//!   the monitor read named a different file than the kernel opened in
//!   **47.6% of 10000 opens** under two threads. Such a path is sound to
//!   **refuse**, **ask** and **report** with — a refusal never ran, and a
//!   question or a report is at worst honest about a wrong name — and it is
//!   never sound to **allow** with.
//!
//! * The paths of the exec boundary — the program file, the working
//!   directory — are read after `execve` destroyed every other thread of the
//!   program, so no thread is left that could rewrite them. They are ground
//!   facts, and so is everything the kernel itself fixed before the program
//!   started.
//!
//! The types below carry that distinction from the construction point of the
//! fact to the match. [`AdvisoryPath`] never converts into [`GroundPath`],
//! and the facts a match that **allows** an action may consume — the
//! exceptions of a rule that holds, and any path condition under an odd
//! number of `not`s, where a match quiets the rule — are of the type
//! [`GroundFacts`], which an advisory path cannot enter. A runtime guard
//! backs the types: the origin of every fact travels with it, and an allow
//! that consults a fact whose marking was flipped fires the guard instead
//! of deciding.

use std::fmt;

/// The true origin of a path fact.
///
/// The value is written once, when the fact is constructed, and travels with
/// it. The public types say the same thing at compile time; this tag is what
/// the runtime guard of the allow path checks, so that a flipped marking (the
/// mutation of the race harness) is caught even though the type says ground.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Read out of the memory of the judged program, or reported by a
    /// sensor or an external observer.
    Advisory,
    /// Fixed where no thread of the judged program can rewrite it.
    Ground,
}

/// A path read out of the memory of the judged program, or reported by a
/// sensor or an external observer.
///
/// The value is sound input for a rule that refuses, asks or reports. It is
/// never sound input for an allow: under two threads the monitor read the
/// wrong path 47.6% of the time, so an allow that rests on it is a coin flip
/// (`docs/DETECTION-RESEARCH.md` section 2).
/// There is no conversion into [`GroundPath`], so the allow path of the
/// engine cannot consume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvisoryPath<'a> {
    /// The path text.
    text: &'a str,
}

impl<'a> AdvisoryPath<'a> {
    /// Wraps a path that came out of the memory of the judged program, or
    /// from a sensor or an observer.
    pub fn new(text: &'a str) -> Self {
        Self { text }
    }

    /// Returns the path text.
    pub fn as_str(&self) -> &'a str {
        self.text
    }

    /// The test mutation of the race harness: this advisory path dressed as
    /// ground.
    ///
    /// The marking flips, the origin tag does not, so the runtime guard of
    /// the allow path catches every allow that consults the forged fact.
    /// Never call this outside a test.
    #[doc(hidden)]
    pub fn forged_as_ground(&self) -> GroundPath<'a> {
        GroundPath {
            text: self.text,
            origin: Origin::Advisory,
        }
    }
}

impl fmt::Display for AdvisoryPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

/// A path that no thread of the judged program can rewrite.
///
/// The paths of the exec boundary are of this kind — `execve` destroys every
/// other thread of the program before the monitor reads them — and so is
/// every path the kernel itself fixed before the program started. Only these
/// facts may back a match that allows an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroundPath<'a> {
    /// The path text.
    text: &'a str,
    /// Where the fact came from. [`GroundPath::new`] writes `Ground`; the
    /// forged constructor of the race harness writes `Advisory`, and the
    /// allow path asserts the tag before it consumes the fact.
    origin: Origin,
}

impl<'a> GroundPath<'a> {
    /// Wraps a path that no thread of the judged program can rewrite.
    pub fn new(text: &'a str) -> Self {
        Self {
            text,
            origin: Origin::Ground,
        }
    }

    /// Returns the path text.
    pub fn as_str(&self) -> &'a str {
        self.text
    }

    /// Returns the path text for a match that allows the action.
    ///
    /// This is the runtime guard behind the type invariant. A ground path
    /// whose marking was flipped — the mutation of the race harness — still
    /// carries its true origin, and an allow must not rest on it: the guard
    /// fires instead of deciding, because a wrong allow is silent and a
    /// crashed engine is not.
    pub(crate) fn allow_text(&self) -> &'a str {
        assert!(
            self.origin == Origin::Ground,
            "an allow consumed the path `{}` although it was read out of the \
             memory of the judged program: the ground marking was flipped",
            self.text
        );
        self.text
    }
}

impl fmt::Display for GroundPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

/// The path fact of one action, with its provenance.
///
/// The engine builds this at the one point where a path enters a match: the
/// subject. A held file open wraps its path as [`PathFact::Advisory`] — the
/// collector read it out of the memory of the judged program at the stop —
/// and the paths of the exec boundary wrap as [`PathFact::Ground`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFact<'a> {
    /// A path read out of the memory of the judged program, or reported by
    /// a sensor or an observer.
    Advisory(AdvisoryPath<'a>),
    /// A path no thread of the judged program can rewrite.
    Ground(GroundPath<'a>),
}

impl PathFact<'_> {
    /// Returns the path text, for a rule that refuses, asks or reports.
    pub fn as_str(&self) -> &str {
        match self {
            PathFact::Advisory(path) => path.as_str(),
            PathFact::Ground(path) => path.as_str(),
        }
    }
}

impl fmt::Display for PathFact<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ground facts of one action: the only facts a match that **allows**
/// the action may consume.
///
/// The exception of a rule that holds is exactly such a match — it switches
/// the rule off, and the action then continues — so the engine evaluates
/// every exception against these facts. A path read out of the memory of the
/// judged program is not among them, and no conversion exists that could put
/// it there:
///
/// ```compile_fail
/// use af_policy::AdvisoryPath;
/// use af_policy::GroundFacts;
///
/// // The collector read this path out of the memory of the judged program
/// // at the seccomp stop.
/// let read_from_target_memory = AdvisoryPath::new("/work/app/.env");
/// // The facts an allow may rest on take a ground path. There is no
/// // conversion from an advisory path, so an allow rule that consumes one
/// // does not compile:
/// let facts = GroundFacts::new(read_from_target_memory);
/// ```
///
/// A path of the exec boundary, which no thread of the judged program can
/// rewrite, enters freely:
///
/// ```
/// use af_policy::facts::GroundPath;
/// use af_policy::GroundFacts;
///
/// // `execve` destroyed every other thread of the program before the
/// // monitor read this path.
/// let exe = GroundPath::new("/usr/bin/psql");
/// let facts = GroundFacts::new(Some(exe));
/// assert_eq!(facts.path().map(|path| path.as_str()), Some("/usr/bin/psql"));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GroundFacts<'a> {
    /// The ground path of the action, when it has one.
    path: Option<GroundPath<'a>>,
}

impl<'a> GroundFacts<'a> {
    /// Gathers the ground facts from a ground path.
    pub fn new(path: Option<GroundPath<'a>>) -> Self {
        Self { path }
    }

    /// Returns the ground path, for the match that allows.
    ///
    /// The returned path is the one object an allow may consult; its text
    /// accessor carries the runtime guard.
    pub fn path(&self) -> Option<&GroundPath<'a>> {
        self.path.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_advisory_path_keeps_its_text_and_its_name() {
        let advisory = AdvisoryPath::new("/work/f_a.txt");
        assert_eq!(advisory.as_str(), "/work/f_a.txt");
        assert_eq!(advisory.to_string(), "/work/f_a.txt");
        assert_eq!(PathFact::Advisory(advisory).as_str(), "/work/f_a.txt");
    }

    #[test]
    fn a_ground_path_keeps_its_text_and_allows_on_it() {
        let ground = GroundPath::new("/usr/bin/psql");
        assert_eq!(ground.as_str(), "/usr/bin/psql");
        assert_eq!(ground.allow_text(), "/usr/bin/psql");
        assert_eq!(PathFact::Ground(ground).as_str(), "/usr/bin/psql");
    }

    #[test]
    #[should_panic(expected = "an allow consumed the path")]
    fn the_guard_fires_on_a_forged_ground_path() {
        let forged = AdvisoryPath::new("/work/f_b.txt").forged_as_ground();
        // The type says ground; the origin tag says advisory, and the allow
        // path checks the tag before it consumes the fact.
        forged.allow_text();
    }

    #[test]
    fn ground_facts_hold_no_path_when_there_is_none() {
        assert!(GroundFacts::new(None).path().is_none());
        let ground = GroundPath::new("/usr/bin/psql");
        assert_eq!(
            GroundFacts::new(Some(ground)).path().map(|p| p.as_str()),
            Some("/usr/bin/psql")
        );
    }
}
