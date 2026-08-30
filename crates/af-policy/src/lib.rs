//! Deterministic policy engine of the Agent Firewall.
//!
//! The crate reads a rule pack in YAML, compiles every pattern one time, and
//! then answers one question: what must the firewall do with this action?
//!
//! The engine uses no model, no network, no clock and no random number. The
//! same input always gives the same verdict.
//!
//! # Example
//!
//! ```
//! use af_core::{Action, EvalContext, PolicyEngine, ProcessInfo, SessionMeta};
//! use af_policy::PolicySet;
//!
//! let policy = PolicySet::builtin().expect("the built-in pack loads");
//! let session = SessionMeta::new(vec!["bash".to_string()], "/work".to_string());
//! let process = ProcessInfo {
//!     pid: 100,
//!     comm: "psql".to_string(),
//!     exe: Some("/usr/bin/psql".to_string()),
//!     argv: vec![
//!         "psql".to_string(),
//!         "-c".to_string(),
//!         "DROP DATABASE customer_prod".to_string(),
//!     ],
//!     ..Default::default()
//! };
//! let action = Action::Exec {
//!     exe: process.exe.clone(),
//!     program: "psql".to_string(),
//!     argv: process.argv.clone(),
//!     cwd: None,
//!     env: Default::default(),
//! };
//! let ancestry = Vec::new();
//! let ctx = EvalContext::new(&session, &action, &process, &ancestry);
//! assert!(policy.evaluate(&ctx).needs_intervention());
//! ```

#![warn(missing_docs)]

mod builtin;
mod glob;
mod lint;
mod matcher;
mod source;
mod testing;

use std::path::{Path, PathBuf};

use af_core::{
    Decision, Error, EvalContext, MarkScope, MemoryEffect, PolicyEngine, Result, RiskLevel,
    RuleInfo, RuleMatch, SessionMemory, Verdict,
};

pub use lint::{Diagnostic, Severity};
pub use testing::{TestFailure, TestReport};

use matcher::{Matcher, Subject};
use source::{DistinctKey, PolicyFile, RuleSource, TestSource, FORMAT_VERSION};

/// One rule after compilation.
#[derive(Debug)]
pub(crate) struct CompiledRule {
    /// Stable identifier of the rule.
    pub(crate) id: String,
    /// Short title of the rule.
    pub(crate) title: String,
    /// Category of the rule.
    pub(crate) category: String,
    /// How dangerous the rule considers the action.
    pub(crate) risk: RiskLevel,
    /// What the rule wants the firewall to do.
    pub(crate) decision: Decision,
    /// Why the rule matched, in words the user can read.
    pub(crate) reason: String,
    /// Links that explain the danger.
    pub(crate) references: Vec<String>,
    /// False switches the rule off.
    pub(crate) enabled: bool,
    /// Where the rule came from.
    pub(crate) source: String,
    /// The condition of the rule.
    pub(crate) matcher: Matcher,
    /// Conditions that switch the rule off for one action.
    pub(crate) exceptions: Vec<Matcher>,
    /// The fact that the session writes down when the rule matches.
    pub(crate) remember: Option<Remember>,
    /// The window and the count that the rule must reach before it fires.
    pub(crate) threshold: Option<Threshold>,
    /// The tests that the rule declares.
    pub(crate) tests: Vec<TestSource>,
}

/// What a rule writes into the memory of the session.
#[derive(Debug, Clone)]
pub(crate) struct Remember {
    /// Name of the mark.
    pub(crate) mark: String,
    /// How far the mark reaches.
    pub(crate) scope: MarkScope,
    /// How long the mark counts, in seconds.
    pub(crate) ttl_seconds: Option<u64>,
}

/// The window and the count that a rule must reach before it fires.
#[derive(Debug, Clone)]
pub(crate) struct Threshold {
    /// Length of the trailing window, in seconds.
    pub(crate) window_seconds: u64,
    /// How many hits the window must hold, this action included.
    pub(crate) at_least: usize,
    /// What makes two hits different.
    pub(crate) distinct: DistinctKey,
}

impl CompiledRule {
    /// Returns true when the rule matches and no exception holds.
    pub(crate) fn matches(&self, subject: &Subject<'_>) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.matcher.matches(subject) {
            return false;
        }
        !self.exceptions.iter().any(|e| e.matches(subject))
    }

    /// Evaluates one action against this rule alone.
    ///
    /// The result says whether the rule fires, and what the session must
    /// write down. A rule with a `threshold` stays quiet until the window
    /// holds enough hits, but it counts the hit in both cases.
    pub(crate) fn evaluate_one(&self, subject: &Subject<'_>) -> (bool, Vec<MemoryEffect>) {
        if !self.matches(subject) {
            return (false, Vec::new());
        }
        let mut effects: Vec<MemoryEffect> = Vec::new();
        if let Some(remember) = &self.remember {
            effects.push(MemoryEffect::SetMark {
                name: remember.mark.clone(),
                scope: remember.scope,
                root: subject.subtree_root(),
                ttl_seconds: remember.ttl_seconds,
            });
        }
        let Some(threshold) = &self.threshold else {
            return (true, effects);
        };
        let key = subject.distinct_key(threshold.distinct);
        let reached = if threshold.distinct == DistinctKey::None {
            subject
                .memory()
                .count_with_current(&self.id, subject.ts(), threshold.window_seconds)
        } else {
            subject.memory().distinct_with_current(
                &self.id,
                subject.ts(),
                threshold.window_seconds,
                key.as_deref(),
            )
        };
        effects.push(MemoryEffect::NoteOccurrence {
            rule_id: self.id.clone(),
            key,
            window_seconds: threshold.window_seconds,
        });
        (reached >= threshold.at_least, effects)
    }

    /// Makes the record that the verdict carries to the user.
    fn to_match(&self) -> RuleMatch {
        RuleMatch {
            rule_id: self.id.clone(),
            title: self.title.clone(),
            category: self.category.clone(),
            risk: self.risk,
            decision: self.decision,
            reason: self.reason.clone(),
        }
    }

    /// Makes the description that `policy list` shows.
    fn to_info(&self) -> RuleInfo {
        let mut kinds = std::collections::BTreeSet::new();
        self.matcher.collect_action_kinds(&mut kinds);
        let mut intents = std::collections::BTreeSet::new();
        self.matcher.collect_write_intents(&mut intents);
        RuleInfo {
            rule_id: self.id.clone(),
            title: self.title.clone(),
            category: self.category.clone(),
            risk: self.risk,
            decision: self.decision,
            source: self.source.clone(),
            disabled: !self.enabled,
            actions: kinds.iter().map(|k| k.label().to_string()).collect(),
            // Only a rule that asks for a read and never for a write needs an
            // open that reads. A rule with both, or with no `write` field at
            // all, is carried by a monitor that observes writes alone.
            needs_read_open: intents.len() == 1 && intents.contains(&false),
            has_threshold: self.threshold.is_some(),
        }
    }
}

/// What one loaded rule file declares about itself.
#[derive(Debug, Clone)]
pub(crate) struct PackInfo {
    /// Name of the pack, for example `builtin.database`.
    pub(crate) name: String,
    /// What the pack protects, in one line.
    pub(crate) description: String,
    /// Where the pack came from.
    pub(crate) source: String,
}

/// A compiled set of deterministic rules.
///
/// The set keeps the rules in load order. The order does not change the
/// verdict, because [`af_core::Verdict::from_matches`] selects the strongest
/// decision of every rule that matched.
#[derive(Debug, Default)]
pub struct PolicySet {
    rules: Vec<CompiledRule>,
    packs: Vec<PackInfo>,
}

impl PolicySet {
    /// Loads the rule pack that ships inside the binary.
    ///
    /// The pack needs no file on disk, so the firewall also works offline and
    /// on a machine with no rule directory.
    pub fn builtin() -> Result<PolicySet> {
        let mut set = PolicySet::default();
        for (name, text) in builtin::FILES {
            let part = PolicySet::from_str(text, name)?;
            set.extend_strict(part)?;
        }
        Ok(set)
    }

    /// Loads rules from files and directories.
    ///
    /// A directory is read one level deep. The loader takes every `*.yaml`
    /// and `*.yml` file of that directory, in name order, so that the result
    /// does not depend on the file system.
    ///
    /// A rule of a file replaces a built-in rule with the same identifier.
    /// Two files that use the same identifier are a load error.
    pub fn load(paths: &[PathBuf], include_builtin: bool) -> Result<PolicySet> {
        let mut set = if include_builtin {
            PolicySet::builtin()?
        } else {
            PolicySet::default()
        };
        let mut from_files = PolicySet::default();
        for path in paths {
            if path.is_dir() {
                for file in read_directory(path)? {
                    from_files.extend_strict(PolicySet::read_file(&file)?)?;
                }
            } else {
                from_files.extend_strict(PolicySet::read_file(path)?)?;
            }
        }
        set.merge(from_files);
        Ok(set)
    }

    /// Loads rules from text. `source` names the origin for messages.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str, source: &str) -> Result<PolicySet> {
        let file: PolicyFile = serde_yaml_ng::from_str(text)
            .map_err(|err| Error::policy(format!("{source}: {err}")))?;
        if file.version != FORMAT_VERSION {
            return Err(Error::policy(format!(
                "{source}: rule format version {} is not supported, expected {FORMAT_VERSION}",
                file.version
            )));
        }
        if file.name.trim().is_empty() {
            return Err(Error::policy(format!("{source}: the pack has no name")));
        }
        let mut set = PolicySet {
            rules: Vec::with_capacity(file.rules.len()),
            packs: vec![PackInfo {
                name: file.name.clone(),
                description: file.description.clone(),
                source: source.to_string(),
            }],
        };
        for rule in &file.rules {
            let compiled = compile_rule(rule, source)?;
            if set.rules.iter().any(|r| r.id == compiled.id) {
                return Err(Error::policy(format!(
                    "{source}: rule id `{}` is used two times in the same file",
                    compiled.id
                )));
            }
            set.rules.push(compiled);
        }
        Ok(set)
    }

    /// Adds the rules of another set.
    ///
    /// A rule of `other` replaces a rule with the same identifier and keeps
    /// the position of the old rule. A local pack can therefore correct a
    /// built-in rule.
    pub fn merge(&mut self, other: PolicySet) {
        for pack in other.packs {
            if !self.packs.iter().any(|p| p.source == pack.source) {
                self.packs.push(pack);
            }
        }
        for rule in other.rules {
            match self.rules.iter_mut().find(|r| r.id == rule.id) {
                Some(slot) => *slot = rule,
                None => self.rules.push(rule),
            }
        }
    }

    /// Returns how many rules are active.
    ///
    /// A rule with `enabled: false` is loaded, but it is not active.
    pub fn len(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// Returns true when no rule is active.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reports problems that do not stop loading.
    ///
    /// The list holds, for example, a rule that can never match, a rule with
    /// no test, and a rule whose risk level and decision do not agree.
    pub fn lint(&self) -> Vec<Diagnostic> {
        lint::lint(&self.rules, &self.packs)
    }

    /// Runs the tests that the rule files declare.
    ///
    /// Every test runs against its own rule only. A test therefore proves
    /// what the rule itself does, and another rule of the pack cannot hide a
    /// mistake.
    pub fn run_tests(&self) -> TestReport {
        testing::run_tests(&self.rules)
    }

    /// Reads one rule file from disk.
    fn read_file(path: &Path) -> Result<PolicySet> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::policy(format!("cannot read `{}`: {err}", path.display())))?;
        PolicySet::from_str(&text, &path.display().to_string())
    }

    /// Adds the rules of another set and refuses a repeated identifier.
    fn extend_strict(&mut self, other: PolicySet) -> Result<()> {
        for pack in other.packs {
            if !self.packs.iter().any(|p| p.source == pack.source) {
                self.packs.push(pack);
            }
        }
        for rule in other.rules {
            if let Some(old) = self.rules.iter().find(|r| r.id == rule.id) {
                return Err(Error::policy(format!(
                    "rule id `{}` is used two times, in `{}` and in `{}`",
                    rule.id, old.source, rule.source
                )));
            }
            self.rules.push(rule);
        }
        Ok(())
    }
}

impl PolicyEngine for PolicySet {
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Verdict {
        let subject = Subject::new(ctx);
        self.judge(&subject).0
    }

    fn evaluate_with_memory(
        &self,
        ctx: &EvalContext<'_>,
        memory: &SessionMemory,
    ) -> (Verdict, Vec<MemoryEffect>) {
        let subject = Subject::with_memory(ctx, memory);
        self.judge(&subject)
    }

    fn rules(&self) -> Vec<RuleInfo> {
        self.rules.iter().map(CompiledRule::to_info).collect()
    }
}

impl PolicySet {
    /// Runs every rule against one action.
    ///
    /// The call reads the memory but never writes it. The effects go back to
    /// the caller in rule order, so two runs of the same trace write the same
    /// records in the same order.
    fn judge(&self, subject: &Subject<'_>) -> (Verdict, Vec<MemoryEffect>) {
        let mut matches: Vec<RuleMatch> = Vec::new();
        let mut effects: Vec<MemoryEffect> = Vec::new();
        for rule in &self.rules {
            let (fires, mut wanted) = rule.evaluate_one(subject);
            effects.append(&mut wanted);
            if fires {
                matches.push(rule.to_match());
            }
        }
        (Verdict::from_matches(matches), effects)
    }
}

/// Compiles one rule and names the file in every message.
fn compile_rule(rule: &RuleSource, source: &str) -> Result<CompiledRule> {
    if rule.id.trim().is_empty() {
        return Err(Error::policy(format!("{source}: a rule has an empty id")));
    }
    let matcher = Matcher::compile(&rule.match_)
        .map_err(|err| Error::policy(format!("{source}: rule `{}`: {err}", rule.id)))?;
    let mut exceptions = Vec::with_capacity(rule.exceptions.len());
    for exception in &rule.exceptions {
        let compiled = Matcher::compile(exception).map_err(|err| {
            Error::policy(format!("{source}: rule `{}`: exception: {err}", rule.id))
        })?;
        exceptions.push(compiled);
    }
    for test in &rule.tests {
        let count = usize::from(test.file_open.is_some())
            + usize::from(test.connect.is_some())
            + usize::from(test.input.is_some());
        if count > 1 {
            return Err(Error::policy(format!(
                "{source}: rule `{}`: test `{}` gives more than one action",
                rule.id, test.name
            )));
        }
        for (index, step) in test.history.iter().enumerate() {
            let count = usize::from(step.file_open.is_some())
                + usize::from(step.connect.is_some())
                + usize::from(step.input.is_some());
            if count > 1 {
                return Err(Error::policy(format!(
                    "{source}: rule `{}`: test `{}`: history step {index} gives more than one action",
                    rule.id, test.name
                )));
            }
        }
    }
    let remember = match &rule.remember {
        None => None,
        Some(remember) => {
            if remember.mark.trim().is_empty() {
                return Err(Error::policy(format!(
                    "{source}: rule `{}`: `remember.mark` has no name",
                    rule.id
                )));
            }
            Some(Remember {
                mark: remember.mark.clone(),
                scope: remember.scope,
                ttl_seconds: remember.ttl_seconds,
            })
        }
    };
    let threshold = match &rule.threshold {
        None => None,
        Some(threshold) => {
            if threshold.window_seconds == 0 {
                return Err(Error::policy(format!(
                    "{source}: rule `{}`: `threshold.window_seconds` must be more than 0",
                    rule.id
                )));
            }
            if threshold.at_least < 2 {
                return Err(Error::policy(format!(
                    "{source}: rule `{}`: `threshold.at_least` must be at least 2, because a count of 1 is a rule with no threshold",
                    rule.id
                )));
            }
            Some(Threshold {
                window_seconds: threshold.window_seconds,
                at_least: threshold.at_least,
                distinct: threshold.distinct,
            })
        }
    };
    Ok(CompiledRule {
        id: rule.id.clone(),
        title: rule.title.clone(),
        category: rule.category.clone(),
        risk: rule.risk,
        decision: rule.decision,
        reason: rule.reason.clone(),
        references: rule.references.clone(),
        enabled: rule.enabled,
        source: source.to_string(),
        matcher,
        exceptions,
        remember,
        threshold,
        tests: rule.tests.clone(),
    })
}

/// Returns the rule files of one directory, in name order.
fn read_directory(path: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(path)
        .map_err(|err| Error::policy(format!("cannot read `{}`: {err}", path.display())))?;
    for entry in entries {
        let entry = entry
            .map_err(|err| Error::policy(format!("cannot read `{}`: {err}", path.display())))?;
        let file = entry.path();
        if !file.is_file() {
            continue;
        }
        let is_rule_file = file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yaml" || e == "yml");
        if is_rule_file {
            files.push(file);
        }
    }
    files.sort();
    Ok(files)
}
