//! The compiled form of a rule condition, and the match itself.
//!
//! The firewall compiles every pattern one time, when it loads the rules. A
//! match at run time reads only the compiled form, because a held process
//! waits while the engine runs.

use std::collections::BTreeMap;

use af_core::{Action, EvalContext, ProcessInfo};
use regex::Regex;

use crate::glob::Glob;
use crate::source::{ActionKind, MatchSource, Words};

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
        })
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
                Some(path) if self.path_prefix.iter().any(|p| path.starts_with(p.as_str())) => {}
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
                if self.cwd_not_prefix.iter().any(|p| cwd.starts_with(p.as_str())) {
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
        add("path_glob", ActionKind::FileOpen, !self.path_glob.is_empty());
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
    }

    /// Returns true when `any_of` is present but holds no condition.
    pub(crate) fn has_empty_any_of(&self) -> bool {
        self.empty_any_of
    }

    /// Returns true when `ancestor_depth_at_least` is zero, which is always true.
    pub(crate) fn has_zero_depth(&self) -> bool {
        self.ancestor_depth_at_least == Some(0)
    }
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
        let compiled = Regex::new(pattern).map_err(|err| {
            format!("field `env.{name}` has a bad pattern `{pattern}`: {err}")
        })?;
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
}

impl<'a> Subject<'a> {
    /// Builds the subject from the context that the monitor gives.
    pub(crate) fn new(ctx: &EvalContext<'a>) -> Self {
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
