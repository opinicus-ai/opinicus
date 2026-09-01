//! The machine-readable session summary of `run --summary`.
//!
//! The summary is the operational artifact of a headless session: one JSON
//! file that names every rule decision of the session with its evidence
//! line and its provenance chain, counts the outcomes a CI job gates on
//! (denied, reported, quarantined, and the questions an interactive session
//! would have asked), and carries the exit code of the run.
//!
//! # Replay consistency
//!
//! Every decision entry is read from the session's own `policy_decision`
//! events — the same record [`agent-firewall replay`](crate::inspect_cmds)
//! evaluates — so a summary is replay-consistent by construction: a replay
//! of the same trace under the same rule pack finds every `rule_id` again
//! with the same decision label. The integration test
//! `the_ci_summary_matches_the_replay_of_the_same_trace` holds that promise.
//!
//! The summary is built only from the recorded events, never from live
//! monitor state, so a session without `--trace` still summarizes and a
//! summary of a trace-backed session is a function of that trace.

use std::collections::HashMap;
use std::path::Path;

use af_core::{Action, ApprovalOutcome, Decision, Event, EventKind};
use af_provenance::ProcessGraph;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::inspect_cmds::session_of;

/// Version of the summary schema.
///
/// A consumer that reads a summary checks this number first; a file with a
/// higher version is a schema the consumer does not know, not a parse error.
const SCHEMA_VERSION: u32 = 1;

/// The summary of one session, as `run --summary` writes it.
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    /// Version of the summary schema.
    pub schema_version: u32,
    /// The facts of the session, from its `session_start` event.
    pub session: SummarySession,
    /// The exit code the run returned, per the contract of `run --help`.
    pub exit_code: i32,
    /// The counts a CI job gates on.
    pub counts: SummaryCounts,
    /// Every rule decision of the session, in event order.
    pub decisions: Vec<SummaryDecision>,
}

/// The session facts of a summary.
#[derive(Debug, Serialize)]
pub struct SummarySession {
    /// Identifier of the session.
    pub session_id: String,
    /// The command the launcher started.
    pub command: Vec<String>,
    /// The working directory of the session.
    pub cwd: String,
    /// Time the session started, in nanoseconds after the Unix epoch.
    pub started_at: u64,
    /// Time of the last recorded event, in nanoseconds after the Unix epoch.
    pub ended_at: u64,
    /// How many processes the session tree held.
    pub process_count: usize,
    /// True when the session ran in the headless CI mode (`run --ci`).
    pub ci: bool,
}

/// The outcome counts of a session.
#[derive(Debug, Default, Serialize)]
pub struct SummaryCounts {
    /// How many decisions the session refused: rule denials and questions
    /// answered with deny or terminate.
    pub denied: usize,
    /// How many rule matches only reported and let the action continue.
    pub reported: usize,
    /// How many quarantines the session ran.
    pub quarantined: usize,
    /// How many questions the session put to its approver. Under `--ci`
    /// every question is denied, so this is the number of questions an
    /// interactive session would have asked.
    pub questions: usize,
}

/// One rule decision of a session.
#[derive(Debug, Serialize)]
pub struct SummaryDecision {
    /// Position of the `policy_decision` event in the session.
    pub seq: u64,
    /// Time of the decision, in nanoseconds after the Unix epoch.
    pub ts: u64,
    /// The process that performed the action.
    pub pid: af_core::Pid,
    /// Stable identifier of the rule that matched.
    pub rule_id: String,
    /// What the rule asked for — the same label a replay of the trace
    /// prints for this rule (`approval-required`, `deny`, `allow`, …).
    pub decision: String,
    /// What the session did about it (`deny`, `allow`, …), or `null` when
    /// no answer exists: a report needs none, and a verdict the kernel
    /// floor already enforces takes no question.
    pub resolved: Option<String>,
    /// The risk level the rule assigns.
    pub risk: String,
    /// The evidence line a person reads: the action, then the title of the
    /// rule that matched it.
    pub evidence: String,
    /// The provenance chain of the acting process, root first: one program
    /// name per process from the session root down to the actor.
    pub provenance: Vec<String>,
}

/// The standing answers of a session, by rule.
///
/// A rule can fire many times in one session. The first fire is a question
/// with its answer; a fire that repeats a remembered answer records no new
/// question, so the newest answer of the rule is the standing answer those
/// fires repeat.
type Standing = HashMap<String, ApprovalOutcome>;

/// Builds the summary of a session from its recorded events.
///
/// `exit_code` is the code the run returns; `ci` says whether the session
/// ran in the headless CI mode.
///
/// # How a decision finds its answer
///
/// The answer of a question follows the question in the record: a held
/// action records its `policy_decision`, then its `approval_requested` and
/// `approval_resolved`, with nothing between — the process waits at the
/// stop, so no other event can slip in. A decision therefore takes the
/// answer that the events right after it name. A decision with no pair
/// after it was never asked — the kernel floor already answered it, or the
/// session repeated an earlier answer — and falls back on the standing
/// answer of its rule, if the record has named one by then.
pub fn build(events: &[Event], exit_code: i32, ci: bool) -> SessionSummary {
    let graph = ProcessGraph::from_trace(events);
    let session = session_of(events);
    let ended_at = events
        .last()
        .map(|event| event.ts)
        .unwrap_or(session.started_at);

    let mut counts = SummaryCounts::default();
    let mut decisions: Vec<SummaryDecision> = Vec::new();
    let mut standing: Standing = HashMap::new();

    for (index, event) in events.iter().enumerate() {
        match &event.kind {
            EventKind::ApprovalResolved {
                rule_id, outcome, ..
            } => {
                standing.insert(rule_id.clone(), *outcome);
            }
            EventKind::ApprovalRequested { .. } => counts.questions += 1,
            EventKind::QuarantineStarted { .. } => counts.quarantined += 1,
            EventKind::PolicyDecision {
                action,
                verdict,
                ancestry,
            } => {
                let own = own_answer(events, index);
                for matched in &verdict.matches {
                    let resolved =
                        resolution_of(matched.decision, &matched.rule_id, own, &standing);
                    if matches!(
                        resolved,
                        Some(ApprovalOutcome::Deny) | Some(ApprovalOutcome::TerminateSession)
                    ) {
                        counts.denied += 1;
                    } else if !matched.decision.needs_intervention() {
                        counts.reported += 1;
                    }
                    decisions.push(SummaryDecision {
                        seq: event.seq,
                        ts: event.ts,
                        pid: event.pid,
                        rule_id: matched.rule_id.clone(),
                        decision: matched.decision.label().to_string(),
                        resolved: resolved.map(|outcome| outcome.label().to_string()),
                        risk: matched.risk.label().to_string(),
                        evidence: format!("{} — {}", action.summary(), matched.title),
                        provenance: provenance_of(event.pid, ancestry, action, &graph),
                    });
                }
            }
            _ => {}
        }
    }

    SessionSummary {
        schema_version: SCHEMA_VERSION,
        session: SummarySession {
            session_id: session.session_id.0.clone(),
            command: session.command,
            cwd: session.cwd,
            started_at: session.started_at,
            ended_at,
            process_count: graph.len(),
            ci,
        },
        exit_code,
        counts,
        decisions,
    }
}

/// Returns the answer that the events right after one decision name for
/// it.
///
/// The exchange of a held action is contiguous in the record — the
/// `policy_decision`, then the question and its answer, then the ruling of
/// a quarantine — because the process waits at the stop while the exchange
/// runs. The look-ahead ends at the first event that is no part of an
/// exchange, so it can never take the answer of a later decision.
fn own_answer(events: &[Event], index: usize) -> Option<ApprovalOutcome> {
    let mut own = None;
    for event in events.iter().skip(index + 1) {
        match &event.kind {
            EventKind::ApprovalResolved { outcome, .. } => own = Some(*outcome),
            EventKind::ApprovalRequested { .. }
            | EventKind::QuarantineStarted { .. }
            | EventKind::QuarantineResolved { .. } => {}
            _ => break,
        }
    }
    own
}

/// Returns what the session did about one matched rule.
///
/// A rule that decides by itself names its decision: `deny` and `terminate`
/// are enforced without a question. A rule that needs a person takes the
/// answer of its own exchange when it has one — under `--ci` that answer is
/// always deny — and otherwise the standing answer of the rule, which is
/// what a repeated fire repeats. A rule that only reports needs no answer.
fn resolution_of(
    decision: Decision,
    rule_id: &str,
    own: Option<ApprovalOutcome>,
    standing: &Standing,
) -> Option<ApprovalOutcome> {
    match decision {
        Decision::Deny => Some(ApprovalOutcome::Deny),
        Decision::Terminate => Some(ApprovalOutcome::TerminateSession),
        Decision::ApprovalRequired => own.or_else(|| standing.get(rule_id).copied()),
        Decision::Allow | Decision::AllowOnce | Decision::AllowSession => None,
    }
}

/// Names the provenance chain of a decision, root first.
///
/// The `policy_decision` event carries the ancestry of the acting process,
/// nearest parent first; the chain is that list reversed, with the actor at
/// the end. The actor's name comes from the graph, and the action is the
/// fallback when the graph holds no record of the process.
fn provenance_of(
    pid: af_core::Pid,
    ancestry: &[af_core::ProcessInfo],
    action: &Action,
    graph: &ProcessGraph,
) -> Vec<String> {
    let mut chain: Vec<String> = ancestry
        .iter()
        .rev()
        .map(|process| process.program_name().to_string())
        .collect();
    let actor = graph
        .process(pid)
        .map(|process| process.program_name().to_string())
        .unwrap_or_else(|| match action {
            Action::Exec { program, .. } => program.clone(),
            _ => format!("pid {pid}"),
        });
    chain.push(actor);
    chain
}

/// Writes a summary to a file, as pretty JSON.
pub fn write(summary: &SessionSummary, path: &Path) -> Result<()> {
    let text =
        serde_json::to_string_pretty(summary).context("cannot serialize the session summary")?;
    std::fs::write(path, text)
        .with_context(|| format!("cannot write the session summary to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::{Pid, ProcessInfo, RiskLevel, RuleMatch, SessionMeta, Verdict};

    /// Makes a session-start event with two processes: a shell that starts
    /// a payload.
    fn start() -> Event {
        let mut meta = SessionMeta::new(vec!["sh".to_string()], "/work".to_string());
        meta.session_id = af_core::SessionId("afw-test-summary".to_string());
        meta.started_at = 1_000;
        Event::new(
            meta.session_id.clone(),
            100,
            EventKind::SessionStart {
                meta: Box::new(meta),
                capabilities: Vec::new(),
            },
        )
    }

    /// Makes an exec event of a process.
    fn exec(seq: u64, pid: Pid, ppid: Pid, comm: &str) -> Event {
        let mut event = Event::new(
            af_core::SessionId("afw-test-summary".to_string()),
            pid,
            EventKind::ProcessExec {
                process: Box::new(ProcessInfo {
                    pid,
                    ppid: Some(ppid),
                    exe: Some(format!("/usr/bin/{comm}")),
                    comm: comm.to_string(),
                    argv: vec![comm.to_string()],
                    ..ProcessInfo::default()
                }),
            },
        );
        event.seq = seq;
        event.ts = 2_000 + seq * 10;
        event
    }

    /// Makes one rule match.
    fn matched(id: &str, decision: Decision) -> RuleMatch {
        RuleMatch {
            rule_id: id.to_string(),
            title: format!("title of {id}"),
            category: "test".to_string(),
            risk: RiskLevel::ApprovalRequired,
            decision,
            reason: String::new(),
            quarantine: false,
        }
    }

    /// Makes a policy-decision event of a payload exec.
    fn decision(seq: u64, matches: Vec<RuleMatch>) -> Event {
        let mut event = Event::new(
            af_core::SessionId("afw-test-summary".to_string()),
            200,
            EventKind::PolicyDecision {
                action: Box::new(Action::Exec {
                    exe: Some("/usr/bin/psql".to_string()),
                    program: "psql".to_string(),
                    argv: vec![
                        "psql".to_string(),
                        "-c".to_string(),
                        "DROP DATABASE x".to_string(),
                    ],
                    cwd: Some("/work".to_string()),
                    env: Default::default(),
                }),
                verdict: Box::new(Verdict::from_matches(matches)),
                ancestry: vec![ProcessInfo {
                    pid: 100,
                    comm: "sh".to_string(),
                    exe: Some("/usr/bin/sh".to_string()),
                    ..ProcessInfo::default()
                }],
            },
        );
        event.seq = seq;
        event.ts = 2_000 + seq * 10;
        event
    }

    /// Makes an approval pair of the payload.
    fn approval(seq: u64, rule: &str, outcome: ApprovalOutcome) -> Vec<Event> {
        let mut requested = Event::new(
            af_core::SessionId("afw-test-summary".to_string()),
            200,
            EventKind::ApprovalRequested {
                action: Box::new(Action::Exec {
                    exe: Some("/usr/bin/psql".to_string()),
                    program: "psql".to_string(),
                    argv: vec!["psql".to_string()],
                    cwd: None,
                    env: Default::default(),
                }),
                rule_id: rule.to_string(),
            },
        );
        requested.seq = seq;
        let mut resolved = Event::new(
            af_core::SessionId("afw-test-summary".to_string()),
            200,
            EventKind::ApprovalResolved {
                rule_id: rule.to_string(),
                outcome,
                waited_ms: 0,
            },
        );
        resolved.seq = seq + 1;
        vec![requested, resolved]
    }

    #[test]
    fn a_denied_question_counts_as_denied_and_names_the_rule() {
        let mut events = vec![
            start(),
            exec(2, 100, 1, "sh"),
            exec(3, 200, 100, "psql"),
            decision(4, vec![matched("test.drop", Decision::ApprovalRequired)]),
        ];
        events.extend(approval(5, "test.drop", ApprovalOutcome::Deny));

        let summary = build(&events, 3, true);

        assert_eq!(summary.exit_code, 3);
        assert_eq!(summary.counts.denied, 1);
        assert_eq!(summary.counts.questions, 1);
        assert_eq!(summary.counts.reported, 0);
        assert_eq!(summary.decisions.len(), 1);
        let one = &summary.decisions[0];
        assert_eq!(one.rule_id, "test.drop");
        assert_eq!(one.decision, "approval-required");
        assert_eq!(one.resolved.as_deref(), Some("deny"));
        assert!(one.evidence.contains("DROP DATABASE x"));
        assert!(one.evidence.contains("title of test.drop"));
        assert_eq!(one.provenance, vec!["sh", "psql"]);
        assert!(summary.session.ci);
    }

    #[test]
    fn a_report_needs_no_answer_and_counts_as_reported() {
        let events = vec![
            start(),
            exec(2, 100, 1, "sh"),
            decision(3, vec![matched("test.report", Decision::Allow)]),
        ];

        let summary = build(&events, 0, false);

        assert_eq!(summary.counts.reported, 1);
        assert_eq!(summary.counts.denied, 0);
        assert_eq!(summary.counts.questions, 0);
        assert_eq!(summary.decisions[0].resolved, None);
        assert_eq!(summary.decisions[0].decision, "allow");
    }

    #[test]
    fn a_rule_that_decides_by_itself_denies_without_a_question() {
        let events = vec![
            start(),
            exec(2, 100, 1, "sh"),
            decision(3, vec![matched("test.hard-deny", Decision::Deny)]),
        ];

        let summary = build(&events, 3, true);

        assert_eq!(summary.counts.denied, 1);
        assert_eq!(summary.counts.questions, 0, "no person was asked");
        assert_eq!(summary.decisions[0].resolved.as_deref(), Some("deny"));
    }

    #[test]
    fn a_repeated_fire_repeats_the_answer_of_the_session() {
        let mut events = vec![
            start(),
            exec(2, 100, 1, "sh"),
            exec(3, 200, 100, "psql"),
            exec(4, 201, 100, "psql"),
            decision(5, vec![matched("test.burst", Decision::ApprovalRequired)]),
        ];
        events.extend(approval(6, "test.burst", ApprovalOutcome::Deny));
        // The second fire repeats the answer silently: a policy decision
        // and no question.
        events.push(decision(
            8,
            vec![matched("test.burst", Decision::ApprovalRequired)],
        ));

        let summary = build(&events, 3, true);

        assert_eq!(summary.counts.questions, 1, "the session asked one time");
        assert_eq!(summary.counts.denied, 2, "both fires were refused");
        assert_eq!(
            summary.decisions[1].resolved.as_deref(),
            Some("deny"),
            "the repeated fire carries the standing answer"
        );
    }

    #[test]
    fn a_quarantine_counts_and_the_session_facts_travel() {
        let mut events = vec![start(), exec(2, 100, 1, "sh")];
        let mut quarantine = Event::new(
            af_core::SessionId("afw-test-summary".to_string()),
            100,
            EventKind::QuarantineStarted {
                rule: "test.quarantine".to_string(),
                evidence: "sensed".to_string(),
            },
        );
        quarantine.seq = 3;
        events.push(quarantine);
        events.extend(approval(4, "test.quarantine", ApprovalOutcome::Deny));

        let summary = build(&events, 3, true);

        assert_eq!(summary.counts.quarantined, 1);
        assert_eq!(summary.session.session_id, "afw-test-summary");
        assert_eq!(summary.session.command, vec!["sh"]);
        assert_eq!(summary.session.process_count, 1, "one process ran");
        assert_eq!(summary.session.ended_at, events.last().unwrap().ts);
    }

    #[test]
    fn a_session_without_events_still_summarizes() {
        let summary = build(&[], 0, false);
        assert_eq!(summary.schema_version, SCHEMA_VERSION);
        assert_eq!(summary.decisions.len(), 0);
        assert_eq!(summary.counts.denied, 0);
        assert_eq!(summary.session.command, vec!["unknown"]);
    }

    #[test]
    fn the_summary_of_an_empty_session_writes_and_reads_back() {
        let summary = build(&[start()], 0, false);
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("summary.json");
        write(&summary, &path).expect("the summary writes");

        let text = std::fs::read_to_string(&path).expect("the file");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["counts"]["denied"], 0);
        assert_eq!(value["decisions"].as_array().map(Vec::len), Some(0));
    }
}
