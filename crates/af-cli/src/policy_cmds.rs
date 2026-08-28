//! The `policy` sub-commands.

use af_core::PolicyEngine;
use af_policy::{PolicySet, Severity};
use anyhow::{Context, Result};

use crate::cli::{PolicyCommand, PolicyOptions};

/// Loads the rules that the options select.
pub fn load_policy(options: &PolicyOptions) -> Result<PolicySet> {
    let set = PolicySet::load(&options.policy, !options.no_builtin)?;
    if set.is_empty() {
        eprintln!("agent-firewall: warning: no rule is active, so nothing is protected");
    }
    Ok(set)
}

/// The action kinds that the monitor of this version really makes.
///
/// The firewall judges a new program and the content that it reads. It does
/// not observe a file open or a network connection yet, because that needs a
/// system-call source that the monitor does not have. A rule that matches only
/// an action kind outside this list can never fire, and the user must know
/// that instead of trusting a rule that is silent.
pub const SUPPORTED_ACTIONS: &[&str] = &["exec", "input"];

/// Returns true when the monitor can ever make an action that the rule matches.
///
/// A rule that names no action kind matches any action, so it is reachable.
pub fn is_reachable(rule: &af_core::RuleInfo) -> bool {
    rule.actions.is_empty()
        || rule
            .actions
            .iter()
            .any(|kind| SUPPORTED_ACTIONS.contains(&kind.as_str()))
}

/// Runs a `policy` sub-command and returns the exit code.
pub fn run(command: PolicyCommand) -> Result<i32> {
    match command {
        PolicyCommand::List { policy, json } => list(policy, json),
        PolicyCommand::Check { paths } => check(paths),
        PolicyCommand::Test { policy } => test(policy),
    }
}

/// Lists every loaded rule.
fn list(options: PolicyOptions, json: bool) -> Result<i32> {
    let set = load_policy(&options)?;
    let mut rules = set.rules();
    rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(0);
    }

    let width = rules.iter().map(|r| r.rule_id.len()).max().unwrap_or(10);
    println!("{:<width$}  {:<18}  {:<18}  TITLE", "RULE", "RISK", "DECISION");
    for rule in &rules {
        let mark = if is_reachable(rule) { "" } else { "  (inactive)" };
        println!(
            "{:<width$}  {:<18}  {:<18}  {}{mark}",
            rule.rule_id,
            rule.risk.label(),
            rule.decision.label(),
            rule.title
        );
    }

    let unreachable: Vec<&af_core::RuleInfo> =
        rules.iter().filter(|r| !is_reachable(r)).collect();
    println!("\n{} rule(s), {} active", rules.len(), rules.len() - unreachable.len());
    if !unreachable.is_empty() {
        eprintln!(
            "\nagent-firewall: {} rule(s) cannot fire on this version, because the\n\
             monitor does not observe the action kind that they need. The monitor\n\
             makes these action kinds: {}.",
            unreachable.len(),
            SUPPORTED_ACTIONS.join(", ")
        );
        for rule in &unreachable {
            eprintln!("  {} (needs {})", rule.rule_id, rule.actions.join(", "));
        }
    }
    Ok(0)
}

/// Validates policy files.
fn check(paths: Vec<std::path::PathBuf>) -> Result<i32> {
    let set = match PolicySet::load(&paths, false) {
        Ok(set) => set,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(1);
        }
    };

    let diagnostics = set.lint();
    let mut errors = 0;
    for diagnostic in &diagnostics {
        let level = match diagnostic.severity {
            Severity::Error => {
                errors += 1;
                "error"
            }
            Severity::Warning => "warning",
        };
        eprintln!(
            "{level}: {} [{}]: {}",
            diagnostic.rule_id, diagnostic.source, diagnostic.message
        );
    }

    if errors > 0 {
        eprintln!("{errors} error(s) in {} rule(s)", set.len());
        return Ok(1);
    }
    println!(
        "{} rule(s) are valid, {} warning(s)",
        set.len(),
        diagnostics.len()
    );
    Ok(0)
}

/// Runs the tests that the policy files declare.
fn test(options: PolicyOptions) -> Result<i32> {
    let set = load_policy(&options).context("cannot load the rules")?;
    let report = set.run_tests();

    for failure in &report.failures {
        eprintln!(
            "FAIL {} :: {} [{}]\n  expected {}, but the engine answered {}",
            failure.rule_id,
            failure.test_name,
            failure.source,
            failure.expected.label(),
            failure.actual.label()
        );
    }

    if report.is_ok() {
        println!("{} policy test(s) passed", report.passed);
        Ok(0)
    } else {
        eprintln!(
            "{} passed, {} failed",
            report.passed,
            report.failures.len()
        );
        Ok(1)
    }
}
