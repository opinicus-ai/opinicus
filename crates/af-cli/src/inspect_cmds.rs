//! The `replay`, `tree` and `doctor` sub-commands.

use af_core::{
    display, Action, EvalContext, Event, EventKind, PolicyEngine, SessionMemory, SessionMeta,
};
use af_provenance::ProcessGraph;
use af_recorder::read_trace;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::{ReplayArgs, TreeArgs};
use crate::normalize;
use crate::policy_cmds::load_policy;

/// Draws the process tree of a recorded trace.
pub fn tree(args: TreeArgs) -> Result<i32> {
    let events = read_trace(&args.trace)
        .with_context(|| format!("cannot read {}", args.trace.display()))?;
    let graph = ProcessGraph::from_trace(&events);
    println!("{}", graph.render_tree());
    Ok(0)
}

/// One result line of a replay.
#[derive(Debug, Serialize)]
struct ReplayHit {
    pid: af_core::Pid,
    program: String,
    rule_id: String,
    risk: String,
    decision: String,
    command: String,
}

/// Evaluates a recorded trace again with the current rules.
///
/// A replay proves that a rule change gives the answer that the author
/// expects, and it needs no dangerous command.
pub fn replay(args: ReplayArgs) -> Result<i32> {
    let events = read_trace(&args.trace)
        .with_context(|| format!("cannot read {}", args.trace.display()))?;
    let policy = load_policy(&args.policy)?;
    let graph = ProcessGraph::from_trace(&events);
    let session = session_of(&events);
    // The baseline comes from the `SessionStart` event of the trace, never
    // from this machine. A replay must read no state of the machine, or the
    // same trace could give two answers.
    let mut memory = SessionMemory::with_baseline(session.baseline.clone());

    let mut hits: Vec<ReplayHit> = Vec::new();
    let mut evaluated = 0usize;

    for event in &events {
        let EventKind::ProcessExec { process } = &event.kind else {
            continue;
        };
        evaluated += 1;
        // A replay must judge a process in the same way as a live session.
        let judged = normalize::for_policy(process);
        let ancestry = graph.ancestry(judged.pid);
        let action = Action::Exec {
            exe: judged.exe.clone(),
            program: judged.program_name().to_string(),
            argv: judged.argv.clone(),
            cwd: judged.cwd.clone(),
            env: judged.env.clone(),
        };
        // The memory carries a fact from an earlier action to this one. The
        // effects are applied in event order, exactly as the live handler
        // does it, so a replay repeats the verdicts of the live session.
        let (verdict, effects) = policy.evaluate_with_memory(
            &EvalContext::new(&session, &action, &judged, &ancestry).at(event.ts),
            &memory,
        );
        for effect in effects {
            memory.apply(effect, event.ts);
        }

        if verdict.matches.is_empty() {
            if args.verbose && !args.json {
                println!("allow      {:>6}  {}", judged.pid, judged.command_line());
            }
            continue;
        }

        if !args.json {
            println!("\n{}", display::explain(&ancestry, &judged, &action, &verdict));
        }
        for matched in &verdict.matches {
            hits.push(ReplayHit {
                pid: judged.pid,
                program: judged.program_name().to_string(),
                rule_id: matched.rule_id.clone(),
                risk: matched.risk.label().to_string(),
                decision: matched.decision.label().to_string(),
                command: judged.command_line(),
            });
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
    } else {
        println!(
            "\n{evaluated} exec event(s) evaluated, {} rule match(es)",
            hits.len()
        );
    }
    Ok(0)
}

/// Reports what the monitor can observe on this machine.
pub fn doctor() -> Result<i32> {
    println!("agent-firewall doctor\n");
    let capabilities = af_monitor::Monitor::capabilities();
    let width = capabilities.iter().map(|c| c.name.len()).max().unwrap_or(20);
    let mut missing_critical = false;
    for capability in &capabilities {
        let mark = if capability.available { "yes" } else { "no " };
        println!(
            "  {mark}  {:<width$}  {}",
            capability.name,
            capability.detail.as_deref().unwrap_or("")
        );
        if !capability.available && capability.name == "exec_interception" {
            missing_critical = true;
        }
    }

    match af_policy::PolicySet::builtin() {
        Ok(set) => {
            let rules = set.rules();
            let inactive = rules
                .iter()
                .filter(|r| !crate::policy_cmds::is_reachable(r))
                .count();
            println!("\n  built-in rules: {}", rules.len());
            if inactive > 0 {
                println!(
                    "  inactive rules: {inactive} (they need an action kind that this\n\
                                       monitor does not observe; run `policy list` for the list)"
                );
            }
        }
        Err(error) => println!("\n  built-in rules: cannot load them ({error})"),
    }

    if missing_critical {
        println!("\nThis machine cannot hold a program before it runs.");
        return Ok(1);
    }
    println!("\nThe firewall can protect this machine.");
    Ok(0)
}

/// Finds the session metadata of a trace, or makes a replacement.
fn session_of(events: &[Event]) -> SessionMeta {
    for event in events {
        if let EventKind::SessionStart { meta, .. } = &event.kind {
            return (**meta).clone();
        }
    }
    let mut meta = SessionMeta::new(vec!["unknown".to_string()], ".".to_string());
    if let Some(first) = events.first() {
        meta.session_id = first.session_id.clone();
    }
    meta
}
