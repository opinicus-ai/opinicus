//! The `replay`, `tree` and `doctor` sub-commands.

use af_core::{
    display, Action, EvalContext, Event, EventKind, InputStream, PolicyEngine, ProcessInfo,
    SessionMemory, SessionMeta, Verdict,
};
use af_provenance::ProcessGraph;
use af_recorder::read_trace;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::{DoctorArgs, ReplayArgs, TreeArgs};
use crate::normalize;
use crate::policy_cmds::load_policy;

/// Draws the process tree of a recorded trace.
pub fn tree(args: TreeArgs) -> Result<i32> {
    let events =
        read_trace(&args.trace).with_context(|| format!("cannot read {}", args.trace.display()))?;
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
    let events =
        read_trace(&args.trace).with_context(|| format!("cannot read {}", args.trace.display()))?;
    // A trace that starts a session and never ends it is the shape an
    // assassination of the monitor leaves: the writer of the record is the
    // monitor itself, so a kill from outside the tree takes no cleanup path
    // and no `session_end` is ever written. The note names the shape after
    // the fact, from the durable lines that survived — the only place this
    // detection can live (`research/bypass/FINDINGS.md`, the hostile
    // same-UID matrix of [af-12]).
    if let Some(monitor) = monitor_of_unended_session(&events) {
        eprintln!(
            "agent-firewall: the trace holds a session_start and no session_end: the session \
             that wrote it never closed its record. Either it still runs, or its monitor \
             (pid {monitor}) died before the end — a kill of the monitor from outside the \
             tree leaves exactly this shape, and no event names the killer."
        );
    }
    let policy = load_policy(&args.policy)?;
    let graph = ProcessGraph::from_trace(&events);
    let session = session_of(&events);
    // The baseline comes from the `SessionStart` event of the trace, never
    // from this machine. A replay must read no state of the machine, or the
    // same trace could give two answers.
    let mut memory = SessionMemory::with_baseline(session.baseline.clone());

    let mut hits: Vec<ReplayHit> = Vec::new();
    let mut counted = Counts::default();

    let mut index = 0;
    while index < events.len() {
        let event = &events[index];
        index += 1;
        // A replay must judge every action that a live session judges, and in
        // the same order. An exec, a file open and a connection all reach the
        // same engine with the same memory.
        let Some((judged, action)) = action_of(event, &graph) else {
            continue;
        };
        counted.add(&action);
        // The live session judges the content of standard input together with
        // the exec, in one verdict, at the time of the exec event. The monitor
        // emits that content directly after the exec event, so the replay
        // takes the same events into the same verdict. Both sides therefore
        // judge the same actions at the same time.
        let mut actions = vec![action];
        actions.extend(input_after(&events, &mut index, event));

        let ancestry = graph.ancestry(judged.pid);
        // The memory carries a fact from an earlier action to this one. The
        // effects are applied in event order, exactly as the live handler
        // does it, so a replay repeats the verdicts of the live session.
        // Every action of this event is judged against the same memory, and
        // the writes follow afterwards. The live handler does exactly that, so
        // an exec cannot change the answer of its own input here either.
        let mut answers: Vec<(Action, Verdict)> = Vec::new();
        let mut wanted = Vec::new();
        for one in actions {
            let (verdict, mut effects) = policy.evaluate_with_memory(
                &EvalContext::new(&session, &one, &judged, &ancestry).at(event.ts),
                &memory,
            );
            wanted.append(&mut effects);
            answers.push((one, verdict));
        }
        for effect in wanted {
            memory.apply(effect, event.ts);
        }
        let verdict = Verdict::from_matches(
            answers
                .iter()
                .flat_map(|(_, verdict)| verdict.matches.iter().cloned())
                .collect(),
        );
        // The reported action is the one that the strongest rule matched, as
        // in a live session, so an input rule names the input and not the
        // command line.
        let action = verdict
            .top_match()
            .and_then(|top| {
                answers
                    .iter()
                    .find(|(_, verdict)| verdict.matches.iter().any(|m| m.rule_id == top.rule_id))
                    .map(|(action, _)| action.clone())
            })
            .unwrap_or_else(|| answers[0].0.clone());

        if verdict.matches.is_empty() {
            if args.verbose && !args.json {
                println!("allow      {:>6}  {}", judged.pid, action.summary());
            }
            continue;
        }

        if !args.json {
            println!(
                "\n{}",
                display::explain(&ancestry, &judged, &action, &verdict)
            );
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
            "\n{} exec, {} file, {} network, {} signal, {} io_uring, {} tamper and {} discrepancy \
             event(s) evaluated, {} rule match(es)",
            counted.exec,
            counted.file,
            counted.network,
            counted.signal,
            counted.uring,
            counted.tamper,
            counted.discrepancy,
            hits.len()
        );
    }
    Ok(0)
}

/// How many events of each kind the replay judged.
#[derive(Debug, Default)]
struct Counts {
    exec: usize,
    file: usize,
    network: usize,
    signal: usize,
    uring: usize,
    tamper: usize,
    discrepancy: usize,
}

impl Counts {
    /// Counts one action.
    fn add(&mut self, action: &Action) {
        match action {
            Action::FileOpen { .. } => self.file += 1,
            Action::NetworkConnect { .. } => self.network += 1,
            Action::SignalSend { .. } => self.signal += 1,
            Action::IoUring { .. } => self.uring += 1,
            Action::Tamper { .. } => self.tamper += 1,
            Action::Discrepancy { .. } => self.discrepancy += 1,
            _ => self.exec += 1,
        }
    }
}

/// Returns the input actions that belong to one exec, and steps over them.
///
/// The monitor emits the content of standard input directly after the exec
/// event of the same process, and the live session judges that content
/// together with the exec, in one verdict, at the time of the exec. The replay
/// therefore takes those events out of the stream here instead of judging them
/// on their own.
///
/// `index` stands after `event` and moves over every event that this call
/// takes.
///
/// # What a trace cannot carry
///
/// A live session also reads the **script** of the process, and no event
/// carries that text, so a replay cannot judge it. `--retention balanced`, the
/// default, drops the content of standard input as well. A replay of such a
/// trace judges the exec alone. See `docs/ARCHITECTURE.md`, section 6.
fn input_after(events: &[Event], index: &mut usize, event: &Event) -> Vec<Action> {
    if !matches!(event.kind, EventKind::ProcessExec { .. }) {
        return Vec::new();
    }
    let mut out = Vec::new();
    while let Some(next) = events.get(*index) {
        let EventKind::StdinWrite { stream, data } = &next.kind else {
            break;
        };
        if next.pid != event.pid || *stream != InputStream::Stdin {
            break;
        }
        *index += 1;
        if data.trim().is_empty() {
            continue;
        }
        out.push(Action::Input {
            source: af_core::InputSource::Stdin,
            data: data.clone(),
        });
    }
    out
}

/// Makes the action of one recorded event, and names the process that acts.
///
/// Returns `None` for an event that carries no action of its own, such as the
/// start of the session or a decision that an earlier run already made.
fn action_of(event: &Event, graph: &ProcessGraph) -> Option<(ProcessInfo, Action)> {
    match &event.kind {
        EventKind::ProcessExec { process } => {
            // A replay must judge a process in the same way as a live session.
            let judged = normalize::for_policy(process);
            let action = Action::Exec {
                exe: judged.exe.clone(),
                program: judged.program_name().to_string(),
                argv: judged.argv.clone(),
                cwd: judged.cwd.clone(),
                env: judged.env.clone(),
            };
            Some((judged, action))
        }
        EventKind::FileOpen { path, write } => {
            let process = actor(event.pid, graph);
            Some((
                process,
                Action::FileOpen {
                    path: path.clone(),
                    write: *write,
                },
            ))
        }
        EventKind::NetworkConnect { addr, port, host } => {
            let process = actor(event.pid, graph);
            Some((
                process,
                Action::NetworkConnect {
                    host: host.clone(),
                    addr: addr.clone(),
                    port: *port,
                },
            ))
        }
        EventKind::SignalSend { target, signal } => {
            let process = actor(event.pid, graph);
            Some((
                process,
                Action::SignalSend {
                    target: *target,
                    signal: *signal,
                },
            ))
        }
        EventKind::IoUring { call } => {
            let process = actor(event.pid, graph);
            Some((process, Action::IoUring { call: *call }))
        }
        EventKind::Tamper { kind, detail } => {
            let process = actor(event.pid, graph);
            Some((
                process,
                Action::Tamper {
                    kind: *kind,
                    detail: detail.clone(),
                },
            ))
        }
        EventKind::Discrepancy { kind, detail } => {
            let process = actor(event.pid, graph);
            Some((
                process,
                Action::Discrepancy {
                    kind: *kind,
                    detail: detail.clone(),
                },
            ))
        }
        _ => None,
    }
}

/// Reads the facts of the process that acted, out of the trace itself.
///
/// A replay reads no state of this machine, so a process that the trace does
/// not name keeps its identifier and nothing else.
fn actor(pid: af_core::Pid, graph: &ProcessGraph) -> ProcessInfo {
    graph
        .process(pid)
        .unwrap_or_else(|| ProcessInfo::from_pid(pid))
}

/// Reports what the monitor can observe on this machine.
pub fn doctor(args: DoctorArgs) -> Result<i32> {
    let filter = crate::run::parse_syscall_filter(&args.syscall_filter)?;
    println!("agent-firewall doctor\n");
    println!("  alpha release: not a production security boundary; false positives and");
    println!("  false negatives are expected (README.md, `The alpha`)\n");
    println!("  system-call filter: {}\n", filter.label());
    let capabilities = af_monitor::Monitor::capabilities(filter);
    let width = capabilities
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(20);
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
                .filter(|r| !crate::policy_cmds::is_reachable(r, filter))
                .count();
            println!("\n  built-in rules: {}", rules.len());
            if inactive > 0 {
                println!(
                    "  inactive rules: {inactive} (they need something that this filter mode\n\
                                       does not observe; run `policy list --syscall-filter {}`\n\
                                       for the list)",
                    filter.label()
                );
            }
        }
        Err(error) => println!("\n  built-in rules: cannot load them ({error})"),
    }

    match af_telemetry::Consent::load(&af_telemetry::Consent::default_path()) {
        Ok(consent) if consent.is_off() => {
            println!("\n  telemetry: off (opt-in, granular; `agent-firewall telemetry status`)");
        }
        Ok(consent) => {
            let granted: Vec<&str> = consent.granted().iter().map(|s| s.label()).collect();
            println!("\n  telemetry: on ({})", granted.join(", "));
        }
        Err(error) => println!("\n  telemetry: the consent file cannot be read ({error})"),
    }

    if missing_critical {
        println!("\nThis machine cannot hold a program before it runs.");
        return Ok(1);
    }
    println!("\nThe firewall can protect this machine.");
    Ok(0)
}

/// Returns the monitor of a session whose trace starts a session and never
/// ends it, and `None` otherwise.
///
/// The launcher and the monitor are one process, so a monitor that an
/// external process kills mid-session writes nothing after the kill: the
/// durable events the recorder already flushed are the whole record, and
/// the missing `session_end` is the marker of the abrupt end. This check
/// reads that marker after the fact — it is the teardown observation of
/// requirement B.6 done at the only moment it can be done, and it is not a
/// boundary: it names the shape of a lost record, it never senses the kill
/// before the loss, and a session that is still running holds the same
/// shape.
fn monitor_of_unended_session(events: &[Event]) -> Option<af_core::Pid> {
    let mut monitor = None;
    for event in events {
        match &event.kind {
            EventKind::SessionStart { meta, .. } => monitor = Some(meta.monitor_pid),
            EventKind::SessionEnd { .. } => return None,
            _ => {}
        }
    }
    monitor
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

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::SessionId;

    /// Makes a session-start event whose session names `monitor`.
    fn started(monitor: af_core::Pid) -> Event {
        let mut meta = SessionMeta::new(vec!["sleep".to_string()], "/tmp".to_string());
        meta.monitor_pid = monitor;
        Event::new(
            meta.session_id.clone(),
            monitor,
            EventKind::SessionStart {
                meta: Box::new(meta),
                capabilities: Vec::new(),
            },
        )
    }

    /// Makes a session-end event.
    fn ended() -> Event {
        Event::new(
            SessionId::from("af-test"),
            1,
            EventKind::SessionEnd {
                exit_code: Some(0),
                process_count: 1,
            },
        )
    }

    #[test]
    fn a_trace_that_never_closes_names_its_monitor() {
        // The shape a monitor killed from outside the tree leaves behind:
        // the durable lines survived, and no session_end was ever written.
        let events = vec![started(42)];
        assert_eq!(monitor_of_unended_session(&events), Some(42));
    }

    #[test]
    fn a_closed_session_is_not_an_abrupt_end() {
        let events = vec![started(42), ended()];
        assert_eq!(monitor_of_unended_session(&events), None);
    }

    #[test]
    fn a_trace_without_a_session_start_stays_quiet() {
        // An emitted-findings trace (af-correlate `--emit`) holds no
        // session of its own and must not read as a lost one.
        let events = vec![ended()];
        assert_eq!(monitor_of_unended_session(&events), None);
        assert_eq!(monitor_of_unended_session(&[]), None);
    }

    #[test]
    fn the_monitor_named_is_the_one_of_the_session() {
        // A monitor that does not know itself yet (pid 0, the placeholder
        // before the root starts) still names the shape, with its zero.
        let events = vec![started(0)];
        assert_eq!(monitor_of_unended_session(&events), Some(0));
    }
}
