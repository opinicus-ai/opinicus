//! The `correlate` sub-command: expected view versus observed view.

use af_core::{Action, EvalContext, Event, EventKind, PolicyEngine, ProcessInfo, SessionId};
use af_correlate::{correlate, read_reg, Options};
use af_provenance::ProcessGraph;
use af_recorder::read_trace;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::CorrelateArgs;
use crate::policy_cmds::load_policy;

/// One disagreement, with every rule that matched it.
#[derive(Debug, Serialize)]
struct FindingLine {
    kind: &'static str,
    pid: af_core::Pid,
    ts: af_core::TimestampNanos,
    detail: String,
    /// The rules that matched, if any.
    matches: Vec<MatchLine>,
}

/// One rule that matched a disagreement.
#[derive(Debug, Serialize)]
struct MatchLine {
    rule_id: String,
    decision: String,
    risk: String,
    quarantine: bool,
    reason: String,
}

/// Compares the record of the in-process sensor with the trace of the
/// monitor, and judges every disagreement with the loaded rules.
///
/// Correlation reads two finished views and never holds a process, so it can
/// ask nothing: the rules that match are reported, exactly as a replay
/// reports the matches of a recorded trace. The command is the engine's
/// product form — the same code judges a live sensor pair in a future
/// release, and a research pair today.
pub fn correlate_cmd(args: CorrelateArgs) -> Result<i32> {
    let product =
        read_trace(&args.trace).with_context(|| format!("cannot read {}", args.trace.display()))?;
    let sensor = read_trace(&args.sensor)
        .with_context(|| format!("cannot read {}", args.sensor.display()))?;
    let reg = read_reg(&args.reg).with_context(|| format!("cannot read {}", args.reg.display()))?;

    let report = correlate(
        &product,
        &sensor,
        &reg,
        &Options {
            stale_ms: args.stale_ms,
            compare_write_opens: args.compare_write_opens,
        },
    );

    let policy = load_policy(&args.policy)?;
    let graph = ProcessGraph::from_trace(&product);
    let session = session_of(&product);

    let mut lines: Vec<FindingLine> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    for finding in &report.findings {
        let process = graph
            .process(finding.pid)
            .unwrap_or_else(|| ProcessInfo::from_pid(finding.pid));
        let ancestry = graph.ancestry(finding.pid);
        let action = Action::Discrepancy {
            kind: finding.kind,
            detail: finding.detail.clone(),
        };
        let verdict = policy
            .evaluate(&EvalContext::new(&session, &action, &process, &ancestry).at(finding.ts));
        let matches = verdict
            .matches
            .iter()
            .map(|matched| MatchLine {
                rule_id: matched.rule_id.clone(),
                decision: matched.decision.label().to_string(),
                risk: matched.risk.label().to_string(),
                quarantine: matched.quarantine,
                reason: matched.reason.clone(),
            })
            .collect();
        lines.push(FindingLine {
            kind: finding.kind.label(),
            pid: finding.pid,
            ts: finding.ts,
            detail: finding.detail.clone(),
            matches,
        });
        let mut event = Event::new(
            SessionId::from(session.session_id.as_str()),
            finding.pid,
            EventKind::Discrepancy {
                kind: finding.kind,
                detail: finding.detail.clone(),
            },
        );
        event.ts = finding.ts;
        events.push(event);
    }

    if let Some(path) = &args.emit {
        emit_events(path, &events)?;
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "trace": args.trace.display().to_string(),
                "sensor": args.sensor.display().to_string(),
                "reg": args.reg.display().to_string(),
                "stale_ms": args.stale_ms,
                "compare_write_opens": args.compare_write_opens,
                "counts": {
                    "instances": report.counts.instances,
                    "external_execs": report.counts.external_execs,
                    "sensor_intents": report.counts.sensor_intents,
                    "external_actions": report.counts.external_actions,
                    "findings": report.counts.findings,
                },
                "findings": lines,
            }))?
        );
    } else {
        for line in &lines {
            println!("{}  pid {}  {}", line.kind, line.pid, line.detail);
            for matched in &line.matches {
                let quarantine = if matched.quarantine {
                    " quarantine"
                } else {
                    ""
                };
                println!(
                    "  -> {} {}: {}{}",
                    matched.decision, matched.rule_id, matched.reason, quarantine
                );
            }
        }
        println!(
            "\n{} sensor instance record(s), {} external exec(s), {} sensor exec \
             intent(s), {} held external action(s): {} disagreement(s)",
            report.counts.instances,
            report.counts.external_execs,
            report.counts.sensor_intents,
            report.counts.external_actions,
            report.counts.findings
        );
        if let Some(path) = &args.emit {
            println!("discrepancy events written to {}", path.display());
        }
    }
    Ok(0)
}

/// Writes the findings as one schema-valid trace.
///
/// A trace is the shared contract: `agent-firewall tree` reads the file back,
/// `agent-firewall replay` judges its events with the current rules, and the
/// research pipeline of `research/threats/` can cite it.
fn emit_events(path: &std::path::Path, events: &[Event]) -> Result<()> {
    use std::io::Write;
    let mut file =
        std::fs::File::create(path).with_context(|| format!("cannot write {}", path.display()))?;
    for event in events {
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
    }
    Ok(())
}

/// Finds the session metadata of a trace, or makes a replacement.
fn session_of(events: &[Event]) -> af_core::SessionMeta {
    for event in events {
        if let EventKind::SessionStart { meta, .. } = &event.kind {
            return (**meta).clone();
        }
    }
    let mut meta = af_core::SessionMeta::new(vec!["unknown".to_string()], ".".to_string());
    if let Some(first) = events.first() {
        meta.session_id = first.session_id.clone();
    }
    meta
}
