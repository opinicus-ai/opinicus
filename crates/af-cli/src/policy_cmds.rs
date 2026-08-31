//! The `policy` sub-commands.

use af_core::PolicyEngine;
use af_monitor::SyscallFilter;
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

/// The action kinds that the monitor makes whatever the filter mode is.
///
/// The exec boundary needs no kernel filter, so `exec` and `input` are
/// always there. The tamper facts ride events that the monitor and the
/// provenance graph make themselves — a program that repeats one the
/// firewall killed, a child that inherits no sensor preload, a descendant
/// that detached, a process that outlived the session — so they are there in
/// every mode too. The discrepancy facts ride the correlation of the two
/// recorded views, which needs no kernel filter either: `correlate` reads
/// finished traces.
pub const ALWAYS_SUPPORTED_ACTIONS: &[&str] = &["exec", "input", "tamper", "discrepancy"];

/// Names every action kind that a session with this filter mode can make.
///
/// The kernel filter decides what a running program shows the firewall, so
/// the list depends on the mode. The command line prints it, and a rule that
/// needs a kind outside the list is marked inactive.
pub fn supported_actions(filter: SyscallFilter) -> Vec<&'static str> {
    let mut kinds = ALWAYS_SUPPORTED_ACTIONS.to_vec();
    if filter.observes_opens() {
        kinds.push("file_open");
        kinds.push("network_connect");
        // The filter holds a signal only when its target is the monitor
        // itself, so the kind exists exactly when the filter does.
        kinds.push("signal_send");
    }
    kinds
}

/// Returns true when the monitor can ever make an action that the rule matches.
///
/// A rule that names no action kind matches any action, so it is reachable.
///
/// A rule whose only file open is an open that **reads** is a case of its
/// own. The write-only filter lets the kernel drop such an open, so the rule
/// stays silent even though the firewall does observe file opens. The user
/// must see that, or a credential file looks watched when it is not.
pub fn is_reachable(rule: &af_core::RuleInfo, filter: SyscallFilter) -> bool {
    if rule.actions.is_empty() {
        return true;
    }
    let supported = supported_actions(filter);
    rule.actions.iter().any(|kind| {
        if !supported.contains(&kind.as_str()) {
            return false;
        }
        if kind == "file_open" && rule.needs_read_open && !filter.observes_read_opens() {
            return false;
        }
        true
    })
}

/// Says in one line why a rule cannot fire under this filter mode.
fn why_inactive(rule: &af_core::RuleInfo, filter: SyscallFilter) -> String {
    if rule.needs_read_open && filter.observes_opens() {
        return "needs the path of an open that reads; run with `--syscall-filter all-opens`"
            .to_string();
    }
    format!("needs {}", rule.actions.join(", "))
}

/// Runs a `policy` sub-command and returns the exit code.
pub fn run(command: PolicyCommand) -> Result<i32> {
    match command {
        PolicyCommand::List {
            policy,
            syscall_filter,
            json,
        } => {
            let filter = crate::run::parse_syscall_filter(&syscall_filter)?;
            list(policy, filter, json)
        }
        PolicyCommand::Check { paths } => check(paths),
        PolicyCommand::Test { policy } => test(policy),
    }
}

/// Lists every loaded rule.
fn list(options: PolicyOptions, filter: SyscallFilter, json: bool) -> Result<i32> {
    let set = load_policy(&options)?;
    let mut rules = set.rules();
    rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(0);
    }

    let width = rules.iter().map(|r| r.rule_id.len()).max().unwrap_or(10);
    println!(
        "{:<width$}  {:<18}  {:<18}  TITLE",
        "RULE", "RISK", "DECISION"
    );
    for rule in &rules {
        let mark = if is_reachable(rule, filter) {
            ""
        } else {
            "  (inactive)"
        };
        println!(
            "{:<width$}  {:<18}  {:<18}  {}{mark}",
            rule.rule_id,
            rule.risk.label(),
            rule.decision.label(),
            rule.title
        );
    }

    let unreachable: Vec<&af_core::RuleInfo> =
        rules.iter().filter(|r| !is_reachable(r, filter)).collect();
    println!(
        "\n{} rule(s), {} active with `--syscall-filter {}`",
        rules.len(),
        rules.len() - unreachable.len(),
        filter.label()
    );
    if !unreachable.is_empty() {
        eprintln!(
            "\nagent-firewall: {} rule(s) cannot fire with `--syscall-filter {}`,\n\
             because the monitor does not observe what they need. The monitor makes\n\
             these action kinds: {}.",
            unreachable.len(),
            filter.label(),
            supported_actions(filter).join(", ")
        );
        for rule in &unreachable {
            eprintln!("  {} ({})", rule.rule_id, why_inactive(rule, filter));
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
        eprintln!("{} passed, {} failed", report.passed, report.failures.len());
        Ok(1)
    }
}
