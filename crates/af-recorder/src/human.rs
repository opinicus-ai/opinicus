//! Text of one event for a person.

use af_core::{
    display::{explain, sanitize, truncate},
    Event, EventKind,
};

/// How many characters of free text one line shows.
const MAX_TEXT: usize = 120;

/// Returns one line that describes an event.
///
/// The line is safe for a terminal: the function removes every control
/// character, so a monitored program cannot write escape sequences into the
/// screen of the user.
pub(crate) fn line(event: &Event) -> String {
    format!(
        "[{:>5}] {:<17} pid {:<7} {}",
        event.seq,
        event.kind_label(),
        event.pid,
        summary(event)
    )
}

/// Returns the full explanation of an event, when the event needs one.
///
/// A decision that holds an action must always be explainable, so the sink
/// prints the chain, the operation, the policy and the decision.
pub(crate) fn detail(event: &Event) -> Option<String> {
    match &event.kind {
        EventKind::PolicyDecision {
            action,
            verdict,
            ancestry,
        } if verdict.needs_intervention() => {
            let process = acting_process(event.pid, action, ancestry);
            Some(explain(ancestry, &process, action, verdict))
        }
        _ => None,
    }
}

/// Rebuilds the facts of the process that acts.
///
/// A decision event holds the action and the ancestry, but not the process
/// itself. An exec action already holds the program and the command line, so
/// the explanation can name the process.
fn acting_process(
    pid: af_core::Pid,
    action: &af_core::Action,
    ancestry: &[af_core::ProcessInfo],
) -> af_core::ProcessInfo {
    let mut process = af_core::ProcessInfo::from_pid(pid);
    if let af_core::Action::Exec {
        exe,
        program,
        argv,
        cwd,
        env,
    } = action
    {
        process.exe = exe.clone();
        process.comm = program.clone();
        process.argv = argv.clone();
        process.cwd = cwd.clone();
        process.env = env.clone();
    }
    process.ppid = ancestry.first().map(|parent| parent.pid);
    process
}

/// Returns the short description of one event.
fn summary(event: &Event) -> String {
    let text = match &event.kind {
        EventKind::SessionStart { meta, capabilities } => {
            let missing = capabilities.iter().filter(|c| !c.available).count();
            format!(
                "{} {} [{}] missing capabilities: {missing}",
                meta.session_id,
                meta.agent.kind.label(),
                meta.command.join(" ")
            )
        }
        EventKind::ProcessFork {
            child_pid,
            is_thread,
        } => {
            if *is_thread {
                format!("thread {child_pid}")
            } else {
                format!("child {child_pid}")
            }
        }
        EventKind::ProcessExec { process } => process.command_line(),
        EventKind::ProcessExit { code, signal } => match (code, signal) {
            (_, Some(signal)) => format!("killed by signal {signal}"),
            (Some(code), _) => format!("exit code {code}"),
            _ => "ended".to_string(),
        },
        EventKind::FileOpen { path, write } => {
            let mode = if *write { "write" } else { "read" };
            format!("{mode} {path}")
        }
        EventKind::NetworkConnect { addr, port, host } => match host {
            Some(host) => format!("{host} ({addr}:{port})"),
            None => format!("{addr}:{port}"),
        },
        EventKind::FileRead { path, data } => {
            format!("read {path}: {}", af_core::display::truncate(data, 60))
        }
        EventKind::FileDelete { path } => format!("delete {path}"),
        EventKind::FileRename { from, to } => format!("rename {from} to {to}"),
        EventKind::LibraryLoad { path } => format!("load {path}"),
        EventKind::EnvChange { name, value } => match value {
            Some(value) => format!("set {name}={value}"),
            None => format!("unset {name}"),
        },
        EventKind::StdinWrite { stream, data } => format!("{stream:?} {data}"),
        EventKind::PolicyDecision {
            action, verdict, ..
        } => {
            let rule = verdict
                .top_match()
                .map(|m| m.rule_id.as_str())
                .unwrap_or("(no rule)");
            format!(
                "{} {} {rule}: {}",
                verdict.decision.label(),
                verdict.risk.label(),
                action.summary()
            )
        }
        EventKind::ApprovalRequested { action, rule_id } => {
            format!("{rule_id}: {}", action.summary())
        }
        EventKind::ApprovalResolved {
            rule_id,
            outcome,
            waited_ms,
        } => format!("{rule_id}: {} after {waited_ms} ms", outcome.label()),
        EventKind::MonitorWarning { message } => message.clone(),
        EventKind::SessionEnd {
            exit_code,
            process_count,
        } => {
            let code = exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            format!("exit code {code}, {process_count} processes")
        }
    };
    sanitize(&truncate(&text, MAX_TEXT))
}
