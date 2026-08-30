//! The compiled form of a rule condition, and the match itself.
//!
//! The firewall compiles every pattern one time, when it loads the rules. A
//! match at run time reads only the compiled form, because a held process
//! waits while the engine runs.

use std::collections::{BTreeMap, BTreeSet};

use af_core::{Action, EvalContext, MarkScope, Pid, ProcessInfo, SessionMemory, TimestampNanos};
use regex::Regex;

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
    not: Option<Box<Matcher>>,
    all_of: Vec<Matcher>,
    any_of: Vec<Matcher>,
    /// True when `any_of` is present but holds no condition.
    empty_any_of: bool,
    marked: Option<MarkedCondition>,
    baseline_missing: Option<BaselineCondition>,
    var_resolves: Option<VarResolvesCondition>,
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
            not: match &source.not {
                Some(inner) => Some(Box::new(Matcher::compile(inner)?)),
                None => None,
            },
            all_of: compile_list(source.all_of.as_deref())?,
            any_of: compile_list(source.any_of.as_deref())?,
            empty_any_of,
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
    pub(crate) fn matches(&self, subject: &Subject<'_>) -> bool {
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
            if !self.exe_glob.iter().any(|g| g.matches(exe)) {
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
            match subject.path {
                Some(path) if self.path.iter().any(|p| p == path) => {}
                _ => return false,
            }
        }
        if !self.path_prefix.is_empty() {
            match subject.path {
                Some(path)
                    if self
                        .path_prefix
                        .iter()
                        .any(|p| path.starts_with(p.as_str())) => {}
                _ => return false,
            }
        }
        if !self.path_glob.is_empty() {
            match subject.path {
                Some(path) if self.path_glob.iter().any(|g| g.matches(path)) => {}
                _ => return false,
            }
        }
        if !self.cwd_prefix.is_empty() {
            match subject.cwd {
                Some(cwd) if self.cwd_prefix.iter().any(|p| cwd.starts_with(p.as_str())) => {}
                _ => return false,
            }
        }
        if !self.cwd_not_prefix.is_empty() {
            if let Some(cwd) = subject.cwd {
                if self
                    .cwd_not_prefix
                    .iter()
                    .any(|p| cwd.starts_with(p.as_str()))
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
            match subject.path {
                Some(path) if pattern.is_match(path) => {}
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
        if let Some(inner) = &self.not {
            if inner.matches(subject) {
                return false;
            }
        }
        if !self.all_of.iter().all(|m| m.matches(subject)) {
            return false;
        }
        if self.empty_any_of {
            return false;
        }
        if !self.any_of.is_empty() && !self.any_of.iter().any(|m| m.matches(subject)) {
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

fn compile_list(source: Option<&[MatchSource]>) -> Result<Vec<Matcher>, CompileError> {
    let Some(list) = source else {
        return Ok(Vec::new());
    };
    list.iter().map(Matcher::compile).collect()
}

/// Every fact of one action, in the form that a match needs.
///
/// The engine builds the subject one time for each evaluation and gives it to
/// every rule. The command line is joined one time only.
#[derive(Debug)]
pub(crate) struct Subject<'a> {
    kind: ActionKind,
    action_program: Option<&'a str>,
    process_program: &'a str,
    exe: Option<&'a str>,
    argv: &'a [String],
    argv_joined: String,
    cwd: Option<&'a str>,
    action_env: Option<&'a BTreeMap<String, String>>,
    process_env: &'a BTreeMap<String, String>,
    path: Option<&'a str>,
    write: Option<bool>,
    host: Option<&'a str>,
    addr: Option<&'a str>,
    port: Option<u16>,
    input: Option<&'a str>,
    ancestry: &'a [ProcessInfo],
    ts: TimestampNanos,
    subtree_root: Pid,
    memory: &'a SessionMemory,
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
            exe: process.exe.as_deref(),
            argv: &process.argv,
            argv_joined: String::new(),
            cwd: process.cwd.as_deref(),
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
                    subject.exe = Some(path);
                }
                if !argv.is_empty() {
                    subject.argv = argv;
                }
                if let Some(dir) = cwd.as_deref() {
                    subject.cwd = Some(dir);
                }
                subject.action_env = Some(env);
            }
            Action::FileOpen { path, write } => {
                subject.path = Some(path.as_str());
                subject.write = Some(*write);
            }
            Action::NetworkConnect { host, addr, port } => {
                subject.host = host.as_deref();
                subject.addr = Some(addr.as_str());
                subject.port = Some(*port);
            }
            Action::Input { data, .. } => {
                subject.input = Some(data.as_str());
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
            DistinctKey::Path => self.path.map(str::to_string),
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
