//! Shows one approval question on the terminal.
//!
//! Run the example with `cargo run -p af-approval --example ask`. The
//! example builds a question about a `psql` command that drops a database.
//! It then asks the same question that the firewall asks.
//!
//! The example proves the most important rule of this crate: the question
//! goes to `/dev/tty` and not to the standard input. Start the example in a
//! pipeline, without a terminal, and the approver denies at once instead of
//! waiting.

use std::time::Duration;

use af_approval::{ApprovalMode, TerminalApprover};
use af_core::{
    Action, ApprovalRequest, Approver, Decision, ProcessInfo, RiskLevel, RuleMatch, SessionMeta,
    Verdict,
};

fn main() {
    let cwd = std::env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "/".to_string());
    let session = SessionMeta::new(vec!["claude".to_string()], cwd.clone());

    let argv = vec![
        "psql".to_string(),
        "-c".to_string(),
        "DROP DATABASE customer_prod".to_string(),
    ];
    let action = Action::Exec {
        exe: Some("/usr/bin/psql".to_string()),
        program: "psql".to_string(),
        argv: argv.clone(),
        cwd: Some(cwd.clone()),
        env: Default::default(),
    };
    let process = ProcessInfo {
        pid: 40,
        ppid: Some(30),
        exe: Some("/usr/bin/psql".to_string()),
        comm: "psql".to_string(),
        argv,
        cwd: Some(cwd),
        ..Default::default()
    };
    let ancestry = vec![
        named("migrate.sh", 30),
        named("bash", 20),
        named("claude", 10),
    ];
    let verdict = Verdict::from_matches(vec![RuleMatch {
        rule_id: "database.destructive.drop-database".to_string(),
        title: "Drop a database".to_string(),
        category: "database".to_string(),
        risk: RiskLevel::ApprovalRequired,
        decision: Decision::ApprovalRequired,
        quarantine: false,
        reason: "the statement removes a whole database".to_string(),
    }]);

    let request = ApprovalRequest {
        session: &session,
        action: &action,
        process: &process,
        ancestry: &ancestry,
        verdict: &verdict,
    };

    let mut approver = TerminalApprover::new(ApprovalMode::automatic())
        .with_timeout(Some(Duration::from_secs(30)));
    let outcome = approver.request(&request);
    println!("outcome: {}", outcome.label());
    println!("stats: {:?}", approver.stats());
}

/// Makes one process of the provenance chain.
fn named(name: &str, pid: i32) -> ProcessInfo {
    ProcessInfo {
        pid,
        exe: Some(format!("/usr/bin/{name}")),
        comm: name.to_string(),
        argv: vec![name.to_string()],
        ..Default::default()
    }
}
