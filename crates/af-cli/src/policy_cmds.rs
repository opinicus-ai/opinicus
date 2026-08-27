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
        println!(
            "{:<width$}  {:<18}  {:<18}  {}",
            rule.rule_id,
            rule.risk.label(),
            rule.decision.label(),
            rule.title
        );
    }
    println!("\n{} rule(s)", rules.len());
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
