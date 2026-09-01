//! The compiled form of a rule condition, and the match itself.
//!
//! The firewall compiles every pattern one time, when it loads the rules. A
//! match at run time reads only the compiled form, because a held process
//! waits while the engine runs.

use std::collections::{BTreeMap, BTreeSet};

use af_core::{Action, EvalContext, MarkScope, Pid, ProcessInfo, SessionMemory, TimestampNanos};
use regex::Regex;

use crate::facts::{AdvisoryPath, GroundFacts, GroundPath, PathFact};
use crate::glob::Glob;
use crate::source::{ActionKind, DistinctKey, MatchSource, VarResolveTarget, Words};

/// An empty memory for a caller that keeps none.
///
/// A rule that asks about an earlier action then finds nothing and stays
/// quiet, which is the safe answer.
static NO_MEMORY: SessionMemory = SessionMemory::new();

/// A compile failure of one condition. The caller adds the rule and the file.
pub(crate) type CompileError = String;

/// One compiled condition.
///
/// Every field that the rule file writes must match. A field that the file
/// does not write is `None` or empty and does not take part in the match.
#[derive(Debug)]
pub(crate) struct Matcher {
    action: Option<ActionKind>,
    program: Vec<String>,
    exe_glob: Vec<Glob>,
    argv_contains: Vec<String>,
    argv_any: Vec<String>,
    argv_matches: Option<Regex>,
    argv_not_matches: Option<Regex>,
    input_matches: Option<Regex>,
    cwd_prefix: Vec<String>,
    cwd_not_prefix: Vec<String>,
    path: Vec<String>,
    path_prefix: Vec<String>,
    path_glob: Vec<Glob>,
    path_matches: Option<Regex>,
    write: Option<bool>,
    host: Vec<String>,
    host_matches: Option<Regex>,
    port: Option<u16>,
    port_in: Vec<u16>,
    parent_program: Vec<String>,
    ancestor_program: Vec<String>,
    ancestor_depth_at_least: Option<usize>,
    env: Vec<(String, Option<Regex>)>,
    signal_target: Vec<SignalTarget>,
    io_uring_calls: Vec<String>,
    evidence_target: Vec<af_core::EvidenceKind>,
    tamper: Vec<String>,
    discrepancy: Vec<String>,
    not: Option<Box<Matcher>>,
    all_of: Vec<Matcher>,
    any_of: Vec<Matcher>,
    /// True when `any_of` is present but holds no condition.
    empty_any_of: bool,
    /// True when this condition, or any condition below it, names the path
    /// of a file open.
    ///
    /// An exception that names a file path is dead — see
    /// [`Matcher::matches_ground`] — and this flag is how the engine knows
    /// without walking the tree at every action.
    names_path: bool,
    marked: Option<MarkedCondition>,
    baseline_missing: Option<BaselineCondition>,
    var_resolves: Option<VarResolvesCondition>,
}

/// The path facts that one evaluation may read.
///
/// One rule condition runs under exactly one view, and the view is the
/// pointer-derived-facts invariant made operational. A path read out of the
/// memory of the judged program (`AdvisoryPath`) was measured wrong 47.6%
/// of the time under two threads (`docs/DETECTION-RESEARCH.md` section 2),
/// so it may be read exactly where a matching condition pushes the verdict
/// toward holding the action:
///
/// * The body of a rule reads every fact. A refusal always held (measured:
///   2000 of 2000 refused calls never ran) and a question or a report is at
///   worst honest about a wrong name.
///
/// * Every position that lets a held action continue reads ground facts
///   only: the exception of a rule that holds, and any block under an odd
///   number of `not`s inside the body, because a match there quiets the
///   rule — the same thing an exception does. The ground text accessor
///   carries the runtime guard: a fact whose marking was flipped fires the
///   guard instead of deciding.
#[derive(Clone, Copy)]
struct PathView<'a> {
    /// The text of every path fact: advisory or ground.
    any: Option<&'a str>,
    /// The ground path of the action, when it has one.
    ground: Option<GroundPath<'a>>,
    /// True in a position where a matching condition lets a held action
    /// continue. Only the ground fact may be read there.
    allow_position: bool,
}

impl<'a> PathView<'a> {
    /// The view of a rule body: every fact is readable.
    fn body(subject: &'a Subject<'_>) -> Self {
        Self::facts(subject).in_allow_position(false)
    }

    /// The view of an exception: ground facts only.
    fn exception(subject: &'a Subject<'_>) -> Self {
        Self::facts(subject).in_allow_position(true)
    }

    /// Gathers both path facts of a subject.
    fn facts(subject: &'a Subject<'_>) -> Self {
        Self {
            any: subject.path.as_ref().map(PathFact::as_str),
            ground: subject.ground_facts().path().copied(),
            allow_position: false,
        }
    }

    /// Returns the same view in the given position.
    fn in_allow_position(self, allow_position: bool) -> Self {
        Self {
            allow_position,
            ..self
        }
    }

    /// The view below one `not`: a match pushes the verdict the other way.
    fn negated(self) -> Self {
        Self {
            allow_position: !self.allow_position,
            ..self
        }
    }

    /// Returns the path text this evaluation may read.
    ///
    /// The allow-position arm consults [`GroundPath::allow_text`], which
    /// asserts the runtime origin of the fact: an allow that consults an
    /// advisory fact dressed as ground fires the guard. A condition that
    /// names no path never calls this, so a flipped marking it does not
    /// consume stays quiet.
    fn text(&self) -> Option<&str> {
        if self.allow_position {
            self.ground.map(|path| path.allow_text())
        } else {
            self.any
        }
    }
}

/// A compiled question about a mark of an earlier action.
#[derive(Debug)]
pub(crate) struct MarkedCondition {
    /// Name of the mark.
    pub(crate) mark: String,
    /// How old the mark may be, in seconds.
    within_seconds: Option<u64>,
    /// How far the reader looks.
    scope: MarkScope,
}

/// A compiled question about a value that the session start did not hold.
#[derive(Debug)]
pub(crate) struct BaselineCondition {
    /// Name of the baseline set.
    set: String,
    /// Pattern with exactly one group over the joined command line.
    capture: Regex,
}

/// A compiled question about a variable token that the child shell expands.
#[derive(Debug)]
pub(crate) struct VarResolvesCondition {
    /// Pattern with exactly one group over the command line: the name.
    capture: Regex,
    /// True when the value may be the home directory of the child.
    home: bool,
    /// True when the value may be the root, or empty.
    root: bool,
}

/// Where a signal goes, in the words of the rule file.
///
/// The words are the B.5 facts: processes of the firewall itself. A rule
/// that names one of them never fires on the signals of a normal session,
/// because no normal program signals the monitor, the session root by
/// firewall order, or a sensor instance the firewall installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalTarget {
    /// The monitor process of this session.
    Monitor,
    /// The root process that the monitor launched.
    SessionRoot,
    /// A process that carries a sensor instance of this session.
    SensorInstance,
    /// Every process the sender can reach (`kill(-1, ...)`), the monitor
    /// included.
    Everything,
    /// Any other process.
    Other,
}

impl SignalTarget {
    /// Reads one word of the rule file.
    fn parse(word: &str) -> Result<Self, String> {
        match word {
            "monitor" => Ok(SignalTarget::Monitor),
            "session_root" => Ok(SignalTarget::SessionRoot),
            "sensor_instance" => Ok(SignalTarget::SensorInstance),
            "everything" => Ok(SignalTarget::Everything),
            "other" => Ok(SignalTarget::Other),
            other => Err(format!(
                "field `signal_target` accepts monitor, session_root, sensor_instance, \
                 everything or other, but it got `{other}`"
            )),
        }
    }
}

impl Matcher {
    /// Compiles one condition.
    ///
    /// The function fails when a pattern is not valid. The message names the
    /// field, so that the user can find the mistake.
    pub(crate) fn compile(source: &MatchSource) -> Result<Self, CompileError> {
        let empty_any_of = source.any_of.as_ref().is_some_and(|list| list.is_empty());
        Ok(Self {
            action: source.action,
            program: words(&source.program),
            exe_glob: globs(&source.exe_glob),
            argv_contains: words(&source.argv_contains),
            argv_any: words(&source.argv_any),
            argv_matches: regex(source.argv_matches.as_deref(), "argv_matches")?,
            argv_not_matches: regex(source.argv_not_matches.as_deref(), "argv_not_matches")?,
            input_matches: regex(source.input_matches.as_deref(), "input_matches")?,
            cwd_prefix: words(&source.cwd_prefix),
            cwd_not_prefix: words(&source.cwd_not_prefix),
            path: words(&source.path),
            path_prefix: words(&source.path_prefix),
            path_glob: globs(&source.path_glob),
            path_matches: regex(source.path_matches.as_deref(), "path_matches")?,
            write: source.write,
            host: words(&source.host),
            host_matches: regex(source.host_matches.as_deref(), "host_matches")?,
            port: source.port,
            port_in: source.port_in.clone().unwrap_or_default(),
            parent_program: words(&source.parent_program),
            ancestor_program: words(&source.ancestor_program),
            ancestor_depth_at_least: source.ancestor_depth_at_least,
            env: compile_env(source.env.as_ref())?,
            signal_target: compile_signal_targets(source.signal_target.as_ref())?,
            io_uring_calls: words(&source.io_uring),
            evidence_target: compile_evidence_targets(source.evidence_target.as_ref())?,
            tamper: words(&source.tamper),
            discrepancy: words(&source.discrepancy),
            not: match &source.not {
                Some(inner) => Some(Box::new(Matcher::compile(inner)?)),
                None => None,
            },
            all_of: compile_list(source.all_of.as_deref())?,
            any_of: compile_list(source.any_of.as_deref())?,
            empty_any_of,
            names_path: names_path(source),
            marked: compile_marked(source)?,
            baseline_missing: compile_baseline(source)?,
            var_resolves: compile_var_resolves(source)?,
        })
    }

    /// Collects every action kind that this condition can match.
    ///
    /// A nested condition can name its own action kind, so the function walks
    /// the whole tree. The result stays empty when no condition names a kind,
    /// which means the rule matches any action.
    pub(crate) fn collect_action_kinds(&self, out: &mut BTreeSet<ActionKind>) {
        if let Some(kind) = self.action {
            out.insert(kind);
        }
        for nested in self.all_of.iter().chain(self.any_of.iter()) {
            nested.collect_action_kinds(out);
        }
        // A `not` block describes what must NOT match, so its action kind
        // says nothing about what the rule can match.
    }

    /// Collects every write intent that this condition asks a file open for.
    ///
    /// `Some(false)` in the answer means that some branch of the rule only
    /// matches an open that reads. A monitor that never observes a read can
    /// then not carry that branch, and the user interface has to say so.
    ///
    /// A `not` block is left out for the same reason as above.
    pub(crate) fn collect_write_intents(&self, out: &mut BTreeSet<bool>) {
        if let Some(write) = self.write {
            out.insert(write);
        }
        for nested in self.all_of.iter().chain(self.any_of.iter()) {
            nested.collect_write_intents(out);
        }
    }

    /// Returns true when every condition of the block matches the action.
    ///
    /// This is the evaluation of a rule **body**, and it reads every fact:
    /// a rule that refuses, asks or reports may match on a path read out of
    /// the memory of the judged program, because a refusal always held
    /// (measured: 2000 of 2000 refused calls never ran) and a question or a
    /// report is at worst honest about a wrong name. A `not` block inside
    /// the body is the exception-shaped position, and the view flips below
    /// it — see [`PathView`].
    pub(crate) fn matches(&self, subject: &Subject<'_>) -> bool {
        self.matches_with(subject, &PathView::body(subject))
    }

    /// Returns true when the exception matches the action.
    ///
    /// This is the evaluation of an **exception**, the one condition that
    /// allows a stopped action: a matched exception switches a rule that
    /// holds off, and the action then continues on the default allow. Such
    /// a match accepts ground facts only — [`GroundFacts`] has no
    /// constructor from an advisory path — and an exception that names a
    /// file path anywhere in its tree is **dead**: it never holds, whatever
    /// the marking, because no read out of the judged program's memory may
    /// decide whether a rule that holds stays quiet. The lint names the dead
    /// exception at load time; the runtime guard behind [`PathView::text`]
    /// catches a fact whose marking was flipped.
    pub(crate) fn matches_ground(&self, subject: &Subject<'_>) -> bool {
        if self.names_path {
            return false;
        }
        self.matches_with(subject, &PathView::exception(subject))
    }

    /// Evaluates one condition block under one view of the path facts.
    fn matches_with(&self, subject: &Subject<'_>, path: &PathView<'_>) -> bool {
        if let Some(kind) = self.action {
            if kind != subject.kind {
                return false;
            }
        }
        if !self.program.is_empty() && !subject.program_is_one_of(&self.program) {
            return false;
        }
        if let Some(port) = self.port {
            if subject.port != Some(port) {
                return false;
            }
        }
        if !self.port_in.is_empty() {
            match subject.port {
                Some(port) if self.port_in.contains(&port) => {}
                _ => return false,
            }
        }
        if let Some(write) = self.write {
            if subject.write != Some(write) {
                return false;
            }
        }
        if !self.exe_glob.is_empty() {
            let Some(exe) = subject.exe else {
                return false;
            };
            if !self.exe_glob.iter().any(|g| g.matches(exe.as_str())) {
                return false;
            }
        }
        if !self.argv_contains.is_empty()
            && !self
                .argv_contains
                .iter()
                .all(|want| subject.argv.iter().any(|arg| arg == want))
        {
            return false;
        }
        if !self.argv_any.is_empty()
            && !self
                .argv_any
                .iter()
                .any(|want| subject.argv.iter().any(|arg| arg == want))
        {
            return false;
        }
        if !self.path.is_empty() {
            match path.text() {
                Some(text) if self.path.iter().any(|p| p == text) => {}
                _ => return false,
            }
        }
        if !self.path_prefix.is_empty() {
            match path.text() {
                Some(text)
                    if self
                        .path_prefix
                        .iter()
                        .any(|p| text.starts_with(p.as_str())) => {}
                _ => return false,
            }
        }
        if !self.path_glob.is_empty() {
            match path.text() {
                Some(text) if self.path_glob.iter().any(|g| g.matches(text)) => {}
                _ => return false,
            }
        }
        if !self.cwd_prefix.is_empty() {
            match subject.cwd {
                Some(cwd)
                    if self
                        .cwd_prefix
                        .iter()
                        .any(|p| cwd.as_str().starts_with(p.as_str())) => {}
                _ => return false,
            }
        }
        if !self.cwd_not_prefix.is_empty() {
            if let Some(cwd) = subject.cwd {
                if self
                    .cwd_not_prefix
                    .iter()
                    .any(|p| cwd.as_str().starts_with(p.as_str()))
                {
                    return false;
                }
            }
        }
        if !self.host.is_empty() && !subject.host_is_one_of(&self.host) {
            return false;
        }
        if !self.parent_program.is_empty() {
            match subject.parent_program() {
                Some(parent) if self.parent_program.iter().any(|p| p == parent) => {}
                _ => return false,
            }
        }
        if !self.ancestor_program.is_empty() && !subject.has_ancestor(&self.ancestor_program) {
            return false;
        }
        if let Some(depth) = self.ancestor_depth_at_least {
            if subject.ancestry.len() < depth {
                return false;
            }
        }
        if let Some(pattern) = &self.argv_matches {
            if !pattern.is_match(&subject.argv_joined) {
                return false;
            }
        }
        if let Some(pattern) = &self.argv_not_matches {
            if pattern.is_match(&subject.argv_joined) {
                return false;
            }
        }
        if let Some(pattern) = &self.path_matches {
            match path.text() {
                Some(text) if pattern.is_match(text) => {}
                _ => return false,
            }
        }
        if let Some(pattern) = &self.host_matches {
            if !subject.host_matches(pattern) {
                return false;
            }
        }
        if let Some(pattern) = &self.input_matches {
            match subject.input {
                Some(text) if pattern.is_match(text) => {}
                _ => return false,
            }
        }
        for (name, value) in &self.env {
            let Some(found) = subject.env_value(name) else {
                return false;
            };
            if let Some(pattern) = value {
                if !pattern.is_match(found) {
                    return false;
                }
            }
        }
        if !self.signal_target.is_empty()
            && !subject
                .signal_target
                .is_some_and(|target| self.signal_target.contains(&target))
        {
            return false;
        }
        if !self.io_uring_calls.is_empty() {
            let Some(call) = subject.io_uring_call else {
                return false;
            };
            if !self.io_uring_calls.iter().any(|want| want == call) {
                return false;
            }
        }
        if !self.evidence_target.is_empty()
            && !subject
                .evidence_target
                .is_some_and(|target| self.evidence_target.contains(&target))
        {
            return false;
        }
        if !self.tamper.is_empty() {
            let Some(kind) = subject.tamper_kind else {
                return false;
            };
            if !self.tamper.iter().any(|want| want == kind) {
                return false;
            }
        }
        if !self.discrepancy.is_empty() {
            let Some(kind) = subject.discrepancy_kind else {
                return false;
            };
            if !self.discrepancy.iter().any(|want| want == kind) {
                return false;
            }
        }
        if let Some(inner) = &self.not {
            // A `not` turns a match into the other direction, so the view
            // flips with it: a path condition under an odd number of `not`s
            // quiets the rule when it matches, which is the allow-shaped
            // position, and only ground facts may decide that.
            if inner.matches_with(subject, &path.negated()) {
                return false;
            }
        }
        if !self.all_of.iter().all(|m| m.matches_with(subject, path)) {
            return false;
        }
        if self.empty_any_of {
            return false;
        }
        if !self.any_of.is_empty() && !self.any_of.iter().any(|m| m.matches_with(subject, path)) {
            return false;
        }
        if let Some(condition) = &self.marked {
            if !subject.has_mark(condition) {
                return false;
            }
        }
        if let Some(condition) = &self.baseline_missing {
            if !subject.baseline_missing(condition) {
                return false;
            }
        }
        if let Some(condition) = &self.var_resolves {
            if !subject.var_resolves(condition) {
                return false;
            }
        }
        true
    }

    /// Walks over this condition and every condition below it.
    pub(crate) fn walk(&self, visit: &mut dyn FnMut(&Matcher)) {
        visit(self);
        if let Some(inner) = &self.not {
            inner.walk(visit);
        }
        for inner in self.all_of.iter().chain(self.any_of.iter()) {
            inner.walk(visit);
        }
    }

    /// Returns the action kind that the block selects, when it selects one.
    pub(crate) fn action(&self) -> Option<ActionKind> {
        self.action
    }

    /// Returns the names of the fields that need one action kind.
    ///
    /// The lint uses the result to find a rule that can never match, for
    /// example a rule for `exec` that asks for a file path.
    pub(crate) fn kind_bound_fields(&self) -> Vec<(&'static str, ActionKind)> {
        let mut out: Vec<(&'static str, ActionKind)> = Vec::new();
        let mut add = |name: &'static str, kind: ActionKind, used: bool| {
            if used {
                out.push((name, kind));
            }
        };
        add("path", ActionKind::FileOpen, !self.path.is_empty());
        add(
            "path_prefix",
            ActionKind::FileOpen,
            !self.path_prefix.is_empty(),
        );
        add(
            "path_glob",
            ActionKind::FileOpen,
            !self.path_glob.is_empty(),
        );
        add(
            "path_matches",
            ActionKind::FileOpen,
            self.path_matches.is_some(),
        );
        add("write", ActionKind::FileOpen, self.write.is_some());
        add("host", ActionKind::NetworkConnect, !self.host.is_empty());
        add(
            "host_matches",
            ActionKind::NetworkConnect,
            self.host_matches.is_some(),
        );
        add("port", ActionKind::NetworkConnect, self.port.is_some());
        add(
            "port_in",
            ActionKind::NetworkConnect,
            !self.port_in.is_empty(),
        );
        add(
            "input_matches",
            ActionKind::Input,
            self.input_matches.is_some(),
        );
        add(
            "signal_target",
            ActionKind::SignalSend,
            !self.signal_target.is_empty(),
        );
        add(
            "io_uring",
            ActionKind::IoUring,
            !self.io_uring_calls.is_empty(),
        );
        add(
            "evidence_target",
            ActionKind::FileOpen,
            !self.evidence_target.is_empty(),
        );
        add("tamper", ActionKind::Tamper, !self.tamper.is_empty());
        add(
            "discrepancy",
            ActionKind::Discrepancy,
            !self.discrepancy.is_empty(),
        );
        out
    }

    /// Returns true when the block holds no condition at all.
    pub(crate) fn is_open(&self) -> bool {
        self.action.is_none()
            && self.program.is_empty()
            && self.exe_glob.is_empty()
            && self.argv_contains.is_empty()
            && self.argv_any.is_empty()
            && self.argv_matches.is_none()
            && self.argv_not_matches.is_none()
            && self.input_matches.is_none()
            && self.cwd_prefix.is_empty()
            && self.cwd_not_prefix.is_empty()
            && self.path.is_empty()
            && self.path_prefix.is_empty()
            && self.path_glob.is_empty()
            && self.path_matches.is_none()
            && self.write.is_none()
            && self.host.is_empty()
            && self.host_matches.is_none()
            && self.port.is_none()
            && self.port_in.is_empty()
            && self.parent_program.is_empty()
            && self.ancestor_program.is_empty()
            && self.ancestor_depth_at_least.is_none()
            && self.env.is_empty()
            && self.signal_target.is_empty()
            && self.io_uring_calls.is_empty()
            && self.evidence_target.is_empty()
            && self.tamper.is_empty()
            && self.discrepancy.is_empty()
            && self.not.is_none()
            && self.all_of.is_empty()
            && self.any_of.is_empty()
            && !self.empty_any_of
            && self.marked.is_none()
            && self.baseline_missing.is_none()
            && self.var_resolves.is_none()
    }

    /// Returns true when `any_of` is present but holds no condition.
    pub(crate) fn has_empty_any_of(&self) -> bool {
        self.empty_any_of
    }

    /// Returns true when `ancestor_depth_at_least` is zero, which is always true.
    pub(crate) fn has_zero_depth(&self) -> bool {
        self.ancestor_depth_at_least == Some(0)
    }

    /// Returns the mark that this block asks about, when it asks about one.
    pub(crate) fn marked(&self) -> Option<&MarkedCondition> {
        self.marked.as_ref()
    }

    /// Returns the names of the path fields this block uses.
    ///
    /// The lint uses this on exceptions: the path of a file open is read out
    /// of the memory of the judged program, an exception is a match that
    /// allows, and such a match accepts ground facts only — so a path
    /// condition in an exception can never hold.
    pub(crate) fn path_field_names(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        if !self.path.is_empty() {
            out.push("path");
        }
        if !self.path_prefix.is_empty() {
            out.push("path_prefix");
        }
        if !self.path_glob.is_empty() {
            out.push("path_glob");
        }
        if self.path_matches.is_some() {
            out.push("path_matches");
        }
        out
    }
}

/// Compiles the `marked` block of a condition.
fn compile_marked(source: &MatchSource) -> Result<Option<MarkedCondition>, CompileError> {
    let Some(marked) = &source.marked else {
        return Ok(None);
    };
    if marked.mark.trim().is_empty() {
        return Err("field `marked.mark` has no name".to_string());
    }
    Ok(Some(MarkedCondition {
        mark: marked.mark.clone(),
        within_seconds: marked.within_seconds,
        scope: marked.scope,
    }))
}

/// Compiles the `baseline_missing` block of a condition.
///
/// The pattern must hold exactly one group, because the group is the value
/// that the rule compares against the baseline set.
fn compile_baseline(source: &MatchSource) -> Result<Option<BaselineCondition>, CompileError> {
    let Some(baseline) = &source.baseline_missing else {
        return Ok(None);
    };
    if baseline.set.trim().is_empty() {
        return Err("field `baseline_missing.set` has no name".to_string());
    }
    let capture = Regex::new(&baseline.capture).map_err(|err| {
        format!(
            "field `baseline_missing.capture` has a bad pattern `{}`: {err}",
            baseline.capture
        )
    })?;
    let groups = capture.captures_len() - 1;
    if groups != 1 {
        return Err(format!(
            "field `baseline_missing.capture` needs exactly one group, but `{}` has {groups}",
            baseline.capture
        ));
    }
    Ok(Some(BaselineCondition {
        set: baseline.set.clone(),
        capture,
    }))
}

/// Compiles the `var_resolves` block of a condition.
///
/// The pattern must hold exactly one group, because the group is the name of
/// the variable that the engine looks up in the environment of the child.
fn compile_var_resolves(
    source: &MatchSource,
) -> Result<Option<VarResolvesCondition>, CompileError> {
    let Some(block) = &source.var_resolves else {
        return Ok(None);
    };
    let capture = Regex::new(&block.capture).map_err(|err| {
        format!(
            "field `var_resolves.capture` has a bad pattern `{}`: {err}",
            block.capture
        )
    })?;
    let groups = capture.captures_len() - 1;
    if groups != 1 {
        return Err(format!(
            "field `var_resolves.capture` needs exactly one group, but `{}` has {groups}",
            block.capture
        ));
    }
    let mut home = false;
    let mut root = false;
    for target in &block.to {
        match target {
            VarResolveTarget::Home => home = true,
            VarResolveTarget::Root => root = true,
        }
    }
    if !home && !root {
        return Err("field `var_resolves.to` names no target".to_string());
    }
    Ok(Some(VarResolvesCondition {
        capture,
        home,
        root,
    }))
}

fn words(source: &Option<Words>) -> Vec<String> {
    source.as_ref().map(|w| w.0.clone()).unwrap_or_default()
}
fn globs(source: &Option<Words>) -> Vec<Glob> {
    source
        .as_ref()
        .map(|w| w.0.iter().map(|p| Glob::new(p)).collect())
        .unwrap_or_default()
}

fn regex(pattern: Option<&str>, field: &str) -> Result<Option<Regex>, CompileError> {
    match pattern {
        Some(text) => Regex::new(text)
            .map(Some)
            .map_err(|err| format!("field `{field}` has a bad pattern `{text}`: {err}")),
        None => Ok(None),
    }
}

fn compile_env(
    source: Option<&BTreeMap<String, String>>,
) -> Result<Vec<(String, Option<Regex>)>, CompileError> {
    let Some(map) = source else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(map.len());
    for (name, pattern) in map {
        if pattern.is_empty() {
            out.push((name.clone(), None));
            continue;
        }
        let compiled = Regex::new(pattern)
            .map_err(|err| format!("field `env.{name}` has a bad pattern `{pattern}`: {err}"))?;
        out.push((name.clone(), Some(compiled)));
    }
    Ok(out)
}

/// Reads the words of `signal_target` and checks every one of them.
fn compile_signal_targets(source: Option<&Words>) -> Result<Vec<SignalTarget>, CompileError> {
    let Some(words) = source else {
        return Ok(Vec::new());
    };
    words
        .0
        .iter()
        .map(|word| {
            SignalTarget::parse(word).map_err(|message| format!("field `signal_target`: {message}"))
        })
        .collect()
}

/// Reads the words of `evidence_target` and checks every one of them.
///
/// The words are the labels of [`af_core::EvidenceKind`] — the B.5 facts of
/// the audit trail: files the launcher itself opened before the session ran.
fn compile_evidence_targets(
    source: Option<&Words>,
) -> Result<Vec<af_core::EvidenceKind>, CompileError> {
    let Some(words) = source else {
        return Ok(Vec::new());
    };
    words
        .0
        .iter()
        .map(|word| {
            af_core::EvidenceKind::from_rule_word(word)
                .map_err(|message| format!("field `evidence_target`: {message}"))
        })
        .collect()
}

fn compile_list(source: Option<&[MatchSource]>) -> Result<Vec<Matcher>, CompileError> {
    let Some(list) = source else {
        return Ok(Vec::new());
    };
    list.iter().map(Matcher::compile).collect()
}

/// Returns true when the condition tree names the path of a file open
/// anywhere — at this block or below a `not`, an `all_of` or an `any_of`.
///
/// The exceptions of a rule that holds are dead when they name a file path,
/// and the flag must see through every grouping a rule file can write.
fn names_path(source: &MatchSource) -> bool {
    let words_of = |field: &Option<Words>| field.as_ref().is_some_and(|w| !w.0.is_empty());
    words_of(&source.path)
        || words_of(&source.path_prefix)
        || words_of(&source.path_glob)
        || source.path_matches.is_some()
        || source.not.as_ref().is_some_and(|inner| names_path(inner))
        || source
            .all_of
            .as_ref()
            .is_some_and(|list| list.iter().any(names_path))
        || source
            .any_of
            .as_ref()
            .is_some_and(|list| list.iter().any(names_path))
}

/// Every fact of one action, in the form that a match needs.
///
/// The engine builds the subject one time for each evaluation and gives it to
/// every rule. The command line is joined one time only. The path facts carry
/// their provenance — see [`crate::facts`] — and the wrapping happens here,
/// at the one point where a path of the action becomes matchable: a held
/// file open wraps as advisory, the paths of the exec boundary as ground.
#[derive(Debug)]
pub(crate) struct Subject<'a> {
    kind: ActionKind,
    action_program: Option<&'a str>,
    process_program: &'a str,
    exe: Option<GroundPath<'a>>,
    argv: &'a [String],
    argv_joined: String,
    cwd: Option<GroundPath<'a>>,
    action_env: Option<&'a BTreeMap<String, String>>,
    process_env: &'a BTreeMap<String, String>,
    path: Option<PathFact<'a>>,
    write: Option<bool>,
    host: Option<&'a str>,
    addr: Option<&'a str>,
    port: Option<u16>,
    input: Option<&'a str>,
    ancestry: &'a [ProcessInfo],
    ts: TimestampNanos,
    subtree_root: Pid,
    memory: &'a SessionMemory,
    signal_target: Option<SignalTarget>,
    io_uring_call: Option<&'a str>,
    evidence_target: Option<af_core::EvidenceKind>,
    tamper_kind: Option<&'a str>,
    discrepancy_kind: Option<&'a str>,
}

impl<'a> Subject<'a> {
    /// Builds the subject from the context that the monitor gives.
    ///
    /// The memory comes from the context. A context with no memory reads an
    /// empty store, so a rule about an earlier action stays quiet.
    pub(crate) fn new(ctx: &EvalContext<'a>) -> Self {
        let memory = ctx.memory.unwrap_or(&NO_MEMORY);
        Subject::with_memory(ctx, memory)
    }

    /// Builds the subject and reads a memory that the caller owns.
    pub(crate) fn with_memory(ctx: &EvalContext<'a>, memory: &'a SessionMemory) -> Self {
        let process = ctx.process;
        let mut subject = Self {
            kind: kind_of(ctx.action),
            action_program: None,
            process_program: process.program_name(),
            // The process facts come from the exec stop, where `execve` has
            // destroyed every other thread of the program: no thread is left
            // that could rewrite them (`docs/DETECTION-RESEARCH.md` section
            // 2), so they are ground facts.
            exe: process.exe.as_deref().map(GroundPath::new),
            argv: &process.argv,
            argv_joined: String::new(),
            cwd: process.cwd.as_deref().map(GroundPath::new),
            action_env: None,
            process_env: &process.env,
            path: None,
            write: None,
            host: None,
            addr: None,
            port: None,
            input: None,
            ancestry: ctx.ancestry,
            ts: ctx.ts,
            subtree_root: ctx.subtree_root(),
            memory,
            signal_target: None,
            io_uring_call: None,
            evidence_target: None,
            tamper_kind: None,
            discrepancy_kind: None,
        };
        match ctx.action {
            Action::Exec {
                exe,
                program,
                argv,
                cwd,
                env,
            } => {
                subject.action_program = if program.is_empty() {
                    exe.as_deref().map(basename)
                } else {
                    Some(program.as_str())
                };
                if let Some(path) = exe.as_deref() {
                    // The program path of an exec action is read at the exec
                    // stop, after `execve` destroyed every other thread: a
                    // ground fact.
                    subject.exe = Some(GroundPath::new(path));
                }
                if !argv.is_empty() {
                    subject.argv = argv;
                }
                if let Some(dir) = cwd.as_deref() {
                    subject.cwd = Some(GroundPath::new(dir));
                }
                subject.action_env = Some(env);
            }
            Action::FileOpen { path, write } => {
                // The path of a held open is the one the collector read out
                // of the memory of the judged program at the stop
                // (`docs/ARCHITECTURE.md` section 3a, step 4). It is
                // advisory: under two threads it named a file the kernel
                // did not open 47.6% of the time, so it may refuse, ask and
                // report, and it can never be the reason the action
                // continues.
                subject.path = Some(PathFact::Advisory(AdvisoryPath::new(path.as_str())));
                subject.write = Some(*write);
                // The B.5 facts of the audit trail answer the one question a
                // tamper rule may ask about a file open: is the path a file
                // the firewall itself opened? A path that names no such file
                // is not a fact of the firewall, and no rule of this shape
                // may fire on it.
                subject.evidence_target = ctx.session.evidence_kind(path);
            }
            Action::NetworkConnect { host, addr, port } => {
                subject.host = host.as_deref();
                subject.addr = Some(addr.as_str());
                subject.port = Some(*port);
            }
            Action::Input { data, .. } => {
                subject.input = Some(data.as_str());
            }
            Action::SignalSend { target, .. } => {
                // The B.5 facts answer the only question a tamper rule may
                // ask about a signal: is the target a process of the
                // firewall itself? A signal to anything else is not a fact
                // of the firewall, and no rule of this shape may fire on it.
                // `kill(-1, ...)` is the one exception that names nobody:
                // the kernel filter holds it precisely because it reaches
                // the monitor with everything else.
                let session = ctx.session;
                subject.signal_target = Some(if *target == -1 {
                    SignalTarget::Everything
                } else if session.is_monitor(*target) {
                    SignalTarget::Monitor
                } else if session.is_session_root(*target) {
                    SignalTarget::SessionRoot
                } else if session.is_sensor_instance(*target) {
                    SignalTarget::SensorInstance
                } else {
                    SignalTarget::Other
                });
            }
            Action::Tamper { kind, .. } => {
                subject.tamper_kind = Some(kind.label());
            }
            Action::IoUring { call } => {
                subject.io_uring_call = Some(call.label());
            }
            Action::Discrepancy { kind, .. } => {
                subject.discrepancy_kind = Some(kind.label());
            }
        }
        subject.argv_joined = subject.argv.join(" ");
        subject
    }

    /// Returns true when one of the names is the program of the action.
    fn program_is_one_of(&self, names: &[String]) -> bool {
        if let Some(program) = self.action_program {
            if names.iter().any(|n| n == program) {
                return true;
            }
        }
        !self.process_program.is_empty() && names.iter().any(|n| n == self.process_program)
    }

    /// Returns the program name of the nearest parent process.
    fn parent_program(&self) -> Option<&str> {
        self.ancestry.first().map(|p| p.program_name())
    }

    /// Returns true when one of the names is in the ancestry.
    fn has_ancestor(&self, names: &[String]) -> bool {
        self.ancestry
            .iter()
            .any(|p| names.iter().any(|n| n == p.program_name()))
    }

    /// Returns true when one of the names is the host or the address.
    fn host_is_one_of(&self, names: &[String]) -> bool {
        if let Some(host) = self.host {
            if names.iter().any(|n| n == host) {
                return true;
            }
        }
        match self.addr {
            Some(addr) => names.iter().any(|n| n == addr),
            None => false,
        }
    }

    /// Returns true when the pattern matches the host or the address.
    fn host_matches(&self, pattern: &Regex) -> bool {
        if let Some(host) = self.host {
            if pattern.is_match(host) {
                return true;
            }
        }
        match self.addr {
            Some(addr) => pattern.is_match(addr),
            None => false,
        }
    }

    /// Returns true when a live mark answers the question of the condition.
    fn has_mark(&self, condition: &MarkedCondition) -> bool {
        self.memory.has_mark(
            &condition.mark,
            self.ts,
            condition.within_seconds,
            condition.scope,
            self.subtree_root,
        )
    }

    /// Returns true when the captured value is not in the baseline set.
    ///
    /// The answer is false when the pattern captures nothing, and also when
    /// the session recorded no set with this name. An unknown set would make
    /// every value look new, and a rule that fires on everything is worse
    /// than a rule that stays quiet.
    fn baseline_missing(&self, condition: &BaselineCondition) -> bool {
        let Some(found) = condition.capture.captures(&self.argv_joined) else {
            return false;
        };
        let Some(value) = found.get(1).map(|m| m.as_str()) else {
            return false;
        };
        match self.memory.baseline_has(&condition.set, value) {
            Some(known) => !known,
            None => false,
        }
    }

    /// Returns true when a variable token of the command line, or of the
    /// input text, expands to a target that the condition names.
    ///
    /// The value comes from the environment of the child, never from the
    /// command line: the shell that runs the command is the only judge that
    /// matters, and an approval layer that reads the value anywhere else has
    /// approved the wrong command more than once. A name that the environment
    /// does not hold keeps the condition quiet, because a missing name says
    /// nothing about the value the child will see.
    fn var_resolves(&self, condition: &VarResolvesCondition) -> bool {
        let text = match self.kind {
            ActionKind::Exec => Some(self.argv_joined.as_str()),
            ActionKind::Input => self.input,
            _ => None,
        };
        let Some(text) = text else {
            return false;
        };
        let home = self.env_value("HOME").map(without_trailing_slash);
        for found in condition.capture.captures_iter(text) {
            let Some(name) = found.get(1) else {
                continue;
            };
            let Some(value) = self.env_value(name.as_str()) else {
                continue;
            };
            let value = without_trailing_slash(value);
            let root = value.is_empty();
            let home = home.is_some_and(|h| !h.is_empty() && value == h);
            if (condition.root && root) || (condition.home && home) {
                return true;
            }
        }
        false
    }

    /// Returns the value that makes two hits of a rule different.
    pub(crate) fn distinct_key(&self, kind: DistinctKey) -> Option<String> {
        match kind {
            DistinctKey::None => None,
            DistinctKey::Path => self.path.as_ref().map(|path| path.as_str().to_string()),
            DistinctKey::Host => self.host.or(self.addr).map(str::to_string),
            DistinctKey::Program => self
                .action_program
                .filter(|name| !name.is_empty())
                .or(Some(self.process_program))
                .filter(|name| !name.is_empty())
                .map(str::to_string),
            DistinctKey::ArgvJoined => {
                if self.argv_joined.is_empty() {
                    None
                } else {
                    Some(self.argv_joined.clone())
                }
            }
        }
    }

    /// Returns the time of the action.
    pub(crate) fn ts(&self) -> TimestampNanos {
        self.ts
    }

    /// Returns the root of the process subtree that performs the action.
    pub(crate) fn subtree_root(&self) -> Pid {
        self.subtree_root
    }

    /// Returns the memory that the subject reads.
    pub(crate) fn memory(&self) -> &SessionMemory {
        self.memory
    }

    /// Returns the ground facts of this action: the facts a match that
    /// **allows** the action may consume.
    ///
    /// The ground path is the only fact that needs gathering — the paths of
    /// the exec boundary sit on the subject already, typed as ground. A
    /// path read out of the memory of the judged program is not here, and
    /// nothing can put it here: [`GroundFacts`] takes a [`GroundPath`], and
    /// no conversion from an advisory path exists.
    pub(crate) fn ground_facts(&self) -> GroundFacts<'a> {
        GroundFacts::new(match self.path {
            Some(PathFact::Ground(path)) => Some(path),
            _ => None,
        })
    }

    /// Returns the value of an environment name of the action or the process.
    fn env_value(&self, name: &str) -> Option<&str> {
        if let Some(env) = self.action_env {
            if let Some(value) = env.get(name) {
                return Some(value.as_str());
            }
        }
        self.process_env.get(name).map(|v| v.as_str())
    }
}

/// Returns the action kind of an action.
fn kind_of(action: &Action) -> ActionKind {
    match action {
        Action::Exec { .. } => ActionKind::Exec,
        Action::FileOpen { .. } => ActionKind::FileOpen,
        Action::NetworkConnect { .. } => ActionKind::NetworkConnect,
        Action::Input { .. } => ActionKind::Input,
        Action::SignalSend { .. } => ActionKind::SignalSend,
        Action::IoUring { .. } => ActionKind::IoUring,
        Action::Tamper { .. } => ActionKind::Tamper,
        Action::Discrepancy { .. } => ActionKind::Discrepancy,
    }
}

/// Returns the last part of a path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Returns the path without trailing slashes, so that `/Users/simon/` and
/// `/Users/simon` compare equal. The root becomes the empty string, which an
/// empty value also produces when the token carries a trailing slash.
fn without_trailing_slash(path: &str) -> &str {
    path.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::AdvisoryPath;
    use crate::PolicySet;
    use af_core::{Action, Decision, EvalContext, PolicyEngine, ProcessInfo, SessionMeta};

    /// A rule file with one rule that holds every write open unless a
    /// ground path says otherwise, one rule whose exception names the path
    /// the monitor read (the unsound allowlist of the race, the exact shape
    /// that `research/spikes/seccomp-unotify/src/toctou_open.c` measured),
    /// and one rule that shows the parity: a path under two `not`s is a
    /// condition of the body again, so every fact is readable.
    const RULES: &str = "
version: 1
name: test.race
rules:
  - id: test.race.deny-write
    title: Deny every write open
    category: test
    risk: blocked
    decision: deny
    reason: test
    match:
      action: file_open
      write: true
      not: { path_glob: '**/f_*.txt' }
  - id: test.race.ask-etc
    title: Ask before a write under /etc
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: file_open, write: true, path_prefix: [/etc] }
    exceptions:
      - path_prefix: /etc/static
  - id: test.race.double-not
    title: A path under two nots is a body condition
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match:
      action: file_open
      write: true
      not: { not: { path_prefix: /etc } }
";

    /// A rule file whose exception names a fact of the exec boundary, which
    /// no thread of the judged program can rewrite after the stop.
    const GROUND_RULES: &str = "
version: 1
name: test.ground
rules:
  - id: test.ground.ask-curl
    title: Ask before curl runs
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: exec, program: [curl] }
    exceptions:
      - argv_contains: [--version]
";

    fn context(action: &Action) -> (SessionMeta, ProcessInfo) {
        let session = SessionMeta::new(vec!["bash".to_string()], "/work".to_string());
        let process = ProcessInfo {
            pid: 100,
            comm: "sh".to_string(),
            argv: vec!["sh".to_string()],
            ..Default::default()
        };
        let _ = EvalContext::new(&session, action, &process, &[]);
        (session, process)
    }

    /// Evaluates one action against one rule file.
    fn verdict_of(rules: &str, action: &Action) -> af_core::Verdict {
        let set = PolicySet::from_str(rules, "test").expect("the rule file loads");
        let (session, process) = context(action);
        let ctx = EvalContext::new(&session, action, &process, &[]);
        set.evaluate(&ctx)
    }

    /// The negative of the compile gate: a rule that stops or asks still
    /// matches a path read out of the memory of the judged program. A
    /// refusal always held — measured, 2000 of 2000 refused calls never ran
    /// — and a question is honest at worst about a wrong name.
    #[test]
    fn a_rule_that_stops_or_asks_matches_a_path_read_from_the_judged_program() {
        let open = Action::FileOpen {
            path: "/etc/passwd".to_string(),
            write: true,
        };
        let verdict = verdict_of(RULES, &open);
        assert_eq!(verdict.decision, Decision::Deny);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.rule_id == "test.race.ask-etc"),
            "the question must still fire on the advisory path: {:?}",
            verdict.matches
        );

        let elsewhere = Action::FileOpen {
            path: "/work/f_b.txt".to_string(),
            write: true,
        };
        assert_eq!(verdict_of(RULES, &elsewhere).decision, Decision::Deny);
    }

    /// The invariant itself, in its exception form: the one match that
    /// allows an action — the exception of a rule that holds — never
    /// consumes a path read out of the memory of the judged program. The
    /// read can name `/etc/static/manifest` while the kernel opens
    /// `/etc/passwd`, so the exception is dead and the question stands.
    #[test]
    fn an_exception_never_allows_on_a_path_read_from_the_judged_program() {
        let set = PolicySet::from_str(RULES, "test").expect("the rule file loads");
        let (session, process) = context(&Action::Exec {
            exe: None,
            program: "sh".to_string(),
            argv: vec!["sh".to_string()],
            cwd: None,
            env: Default::default(),
        });
        for read in ["/etc/static/manifest", "/etc/passwd"] {
            let action = Action::FileOpen {
                path: read.to_string(),
                write: true,
            };
            let ctx = EvalContext::new(&session, &action, &process, &[]);
            let subject = Subject::new(&ctx);
            assert_eq!(
                subject.path,
                Some(PathFact::Advisory(AdvisoryPath::new(read))),
                "the subject must wrap the open path as advisory"
            );
            let rule = &set.rules[1];
            assert!(
                rule.matches(&subject),
                "the question must stand: the exception names a path, and the path is advisory"
            );
        }
    }

    /// The same invariant under a `not`: a path condition below an odd
    /// number of negations quiets the rule when it matches, which is the
    /// allow-shaped position, so the raced read cannot make the rule go
    /// quiet there either. Below an even number the condition belongs to
    /// the body again, and every fact is readable.
    #[test]
    fn a_not_block_never_quiets_a_rule_on_a_raced_read() {
        let set = PolicySet::from_str(RULES, "test").expect("the rule file loads");
        let (session, process) = context(&Action::Exec {
            exe: None,
            program: "sh".to_string(),
            argv: vec!["sh".to_string()],
            cwd: None,
            env: Default::default(),
        });
        // One `not`: the read can say `f_a.txt` or `f_b.txt`, and neither
        // side may quiet the deny.
        for read in ["/work/f_a.txt", "/work/f_b.txt"] {
            let action = Action::FileOpen {
                path: read.to_string(),
                write: true,
            };
            let ctx = EvalContext::new(&session, &action, &process, &[]);
            let subject = Subject::new(&ctx);
            assert!(
                set.rules[0].matches(&subject),
                "the deny must hold: the `not` names `{read}`, but the path is advisory"
            );
        }
        // Two `not`s: the condition is a body condition again, so the
        // advisory read fires the question, exactly as a plain `path_prefix`
        // would.
        let action = Action::FileOpen {
            path: "/etc/passwd".to_string(),
            write: true,
        };
        let ctx = EvalContext::new(&session, &action, &process, &[]);
        assert!(set.rules[2].matches(&Subject::new(&ctx)));
        let elsewhere = Action::FileOpen {
            path: "/work/app/.env".to_string(),
            write: true,
        };
        let ctx = EvalContext::new(&session, &elsewhere, &process, &[]);
        assert!(!set.rules[2].matches(&Subject::new(&ctx)));
    }

    /// An exception that names a fact of the exec boundary still holds, so
    /// the gate costs the quiet rules nothing.
    #[test]
    fn an_exception_still_allows_on_a_fact_of_the_exec_boundary() {
        let plain = Action::Exec {
            exe: Some("/usr/bin/curl".to_string()),
            program: "curl".to_string(),
            argv: vec!["curl".to_string(), "https://example.com".to_string()],
            cwd: None,
            env: Default::default(),
        };
        assert_eq!(
            verdict_of(GROUND_RULES, &plain).decision,
            Decision::ApprovalRequired
        );

        let excepted = Action::Exec {
            exe: Some("/usr/bin/curl".to_string()),
            program: "curl".to_string(),
            argv: vec!["curl".to_string(), "--version".to_string()],
            cwd: None,
            env: Default::default(),
        };
        assert_eq!(
            verdict_of(GROUND_RULES, &excepted).decision,
            Decision::Allow
        );
    }

    /// A report rule keeps its note on a path read out of the memory of the
    /// judged program, and the note decides nothing: the verdict is the
    /// default allow of a quiet action, carried at the report's risk.
    #[test]
    fn a_report_rule_notes_a_path_read_from_the_judged_program_and_decides_nothing() {
        let set = PolicySet::builtin().expect("the built-in pack loads");
        let open = Action::FileOpen {
            path: "/home/dev/.ssh/id_rsa".to_string(),
            write: false,
        };
        let (session, process) = context(&open);
        let ctx = EvalContext::new(&session, &open, &process, &[]);
        let verdict = set.evaluate(&ctx);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "a note can never make the decision stronger than the default"
        );
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.rule_id == "filesystem.credentials.read"),
            "the report must still fire: {:?}",
            verdict.matches
        );
        assert!(verdict
            .matches
            .iter()
            .all(|m| !m.decision.needs_intervention()));
    }

    /// The runtime guard behind the types: an allow-shaped position (the
    /// `not` block of the deny rule, which quiets the rule when it matches)
    /// consults the ground fact, and a fact whose marking was flipped fires
    /// the guard instead of deciding.
    #[test]
    #[should_panic(expected = "an allow consumed the path")]
    fn the_guard_fires_when_an_allow_consumes_a_flipped_marking() {
        let set = PolicySet::from_str(RULES, "test").expect("the rule file loads");
        let (session, process) = context(&Action::Exec {
            exe: None,
            program: "sh".to_string(),
            argv: vec!["sh".to_string()],
            cwd: None,
            env: Default::default(),
        });
        let action = Action::FileOpen {
            path: "/work/f_a.txt".to_string(),
            write: true,
        };
        let ctx = EvalContext::new(&session, &action, &process, &[]);
        let mut subject = Subject::new(&ctx);
        // The mutation: the advisory path dressed as ground. The type says
        // ground, the origin tag says advisory, and the allow path checks
        // the tag.
        let forged = AdvisoryPath::new("/work/f_a.txt").forged_as_ground();
        subject.path = Some(PathFact::Ground(forged));
        let rule = &set.rules[0];
        rule.matches(&subject);
    }

    /// The race mutation harness.
    ///
    /// The pairs are the shape of the measured race
    /// (`research/spikes/seccomp-unotify/src/toctou_open.c`): thread A opens
    /// one shared path buffer, thread B rewrites `f_a.txt` and `f_b.txt`
    /// into it, and the truth is what `readlink("/proc/self/fd/N")` says the
    /// kernel opened. Every round flips the marking of the read path to
    /// ground — the drift the invariant exists to catch — and one of the two
    /// catchers must take every mutated allow: the guard fires when the
    /// allow-shaped position (the `not` block of the deny rule) consults the
    /// forged fact, and the dead exception of the ask rule never consults
    /// any path at all, so the raced read can never quiet either rule. The
    /// honest marking always leaves the refusal standing.
    ///
    /// The sequence is a fixed xorshift, not a random source: the engine
    /// keeps its determinism rule, and the harness replays the same 1000
    /// rounds on every run.
    #[test]
    fn the_invariant_catches_every_flipped_marking_of_the_race() {
        let set = PolicySet::from_str(RULES, "test").expect("the rule file loads");
        let rule = &set.rules[0];
        let asking = &set.rules[1];
        let (session, process) = context(&Action::Exec {
            exe: None,
            program: "sh".to_string(),
            argv: vec!["sh".to_string()],
            cwd: None,
            env: Default::default(),
        });

        let mut seed: u64 = 0x0AF1_2EED_4760_0001;
        let mut caught = 0;
        let mut held = 0;
        for _ in 0..1000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let read = if seed & 1 == 0 {
                "/work/f_a.txt"
            } else {
                "/work/f_b.txt"
            };
            let action = Action::FileOpen {
                path: read.to_string(),
                write: true,
            };
            let ctx = EvalContext::new(&session, &action, &process, &[]);

            // The honest marking: the refusal holds, whichever side the race
            // picked, because the `not` block of the deny cannot see an
            // advisory path.
            let subject = Subject::new(&ctx);
            assert!(
                rule.matches(&subject),
                "the deny must hold on the honest marking of `{read}`"
            );
            held += 1;

            // The flipped marking: the guard must catch the allow that the
            // `not` block would make.
            let mut mutated = Subject::new(&ctx);
            let forged = AdvisoryPath::new(read).forged_as_ground();
            mutated.path = Some(PathFact::Ground(forged));
            let fired =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rule.matches(&mutated)));
            assert!(
                fired.is_err(),
                "the guard must catch the flipped marking of `{read}`"
            );
            caught += 1;

            // The same race under the ask rule, whose exception names a
            // path: the exception is dead for the honest marking and stays
            // dead for the flipped one, so the raced read can never quiet
            // the rule through it — the structural catcher.
            let etc = if seed & 2 == 0 {
                "/etc/static/manifest"
            } else {
                "/etc/passwd"
            };
            let action = Action::FileOpen {
                path: etc.to_string(),
                write: true,
            };
            let ctx = EvalContext::new(&session, &action, &process, &[]);
            assert!(
                asking.matches(&Subject::new(&ctx)),
                "the ask must stand on the honest marking of `{etc}`: the exception is dead"
            );
            let mut mutated = Subject::new(&ctx);
            let forged = AdvisoryPath::new(etc).forged_as_ground();
            mutated.path = Some(PathFact::Ground(forged));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    asking.matches(&mutated)
                ))
                .is_ok(),
                "the dead exception must hold the ask even for a fact that claims to be ground: `{etc}`"
            );
        }
        assert_eq!(caught, 1000, "every flipped allow was caught");
        assert_eq!(held, 1000, "every honest refusal stood");
        println!("race mutation harness: {caught} of 1000 flipped markings caught by the guard, {held} of 1000 honest refusals held");
    }
}
