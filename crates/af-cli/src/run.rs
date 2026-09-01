//! The `run` sub-command.
//!
//! This module connects every layer of the firewall. It launches the program
//! through the monitor, builds the provenance graph from the event stream,
//! asks the policy engine about each new program, and holds the process while
//! the user answers.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use af_approval::{ApprovalMode, TerminalApprover};
use af_core::{
    display, Action, AgentKind, AgentLink, ApprovalOutcome, ApprovalRequest, DetectionInput,
    DetectorRegistry, EvalContext, Event, EventKind, EventSink, MemoryEffect, MonitorCapability,
    Pid, PolicyEngine, ProcessInfo, SensorMeta, SessionMemory, SessionMeta, TamperKind,
    TimestampNanos, Verdict,
};
use af_monitor::{
    ExecSensed, InputSnapshot, Intercept, Monitor, MonitorConfig, MonitorHandler, SensedTamper,
    SyscallFilter, TreeControl,
};
use af_provenance::ProcessGraph;
use af_recorder::{FanoutSink, MemorySink, Retention, StreamSink, TraceWriter};
use anyhow::{bail, Context, Result};

use crate::cli::RunArgs;
use crate::normalize;
use crate::policy_cmds::load_policy;

/// The exit code that the firewall returns when it stopped the session.
pub const EXIT_BLOCKED: i32 = 3;

/// Prints the alpha disclosure on standard error, before a session starts.
///
/// The first release is explicitly alpha security software
/// ([DIRECTION.md §7]): false positives are expected, false negatives are
/// possible, and it must not be the user's only protection. A user who runs
/// the firewall sees that on every session, not only in the README.
fn print_banner() {
    eprintln!("agent-firewall: alpha release — not a production security boundary");
    eprintln!("agent-firewall: false positives and false negatives are expected; never rely");
    eprintln!("agent-firewall: on it as your only protection (README.md, `The alpha`)");
}

/// A memory sink behind a shared handle.
///
/// The fanout owns the writing end of a session that opted into telemetry,
/// and the launcher reads the same events back after the session ended. A
/// clone of [`MemorySink`] would share nothing, so the handle shares.
#[derive(Clone, Default)]
struct SharedMemory(Arc<Mutex<MemorySink>>);

impl SharedMemory {
    /// Returns the events that the sink collected.
    fn events(&self) -> Vec<Event> {
        self.0.lock().expect("the telemetry sink").events().to_vec()
    }
}

impl EventSink for SharedMemory {
    fn record(&mut self, event: &Event) -> af_core::Result<()> {
        self.0.lock().expect("the telemetry sink").record(event)
    }
}

/// Runs the `run` sub-command and returns the exit code of the process.
pub fn run(args: RunArgs) -> Result<i32> {
    if args.command.is_empty() {
        bail!("no command given after `--`");
    }
    print_banner();

    let cwd = match &args.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let mut session = SessionMeta::new(args.command.clone(), cwd.display().to_string());
    session
        .baseline
        .insert("git_remotes".to_string(), git_remotes(&cwd));
    // The launcher knows the root command before anything runs, so the
    // detection of the agent root happens here, one time, from facts that
    // the session carries from now on: the resolved program, the command
    // line, the working directory, the inherited environment and the
    // dependency manifests of the working directory. The assessment travels
    // inside the session metadata, so a replay reads it from the trace and
    // never detects again.
    //
    // Quiet is the feature. A session the detectors cannot identify carries
    // no tag, and everything downstream stays exactly as it was.
    session.detection = detect_agent_root(&args.command, &cwd);
    if let Some(agent) = &session.detection {
        session.agent.kind = AgentKind::from_agent_name(&agent.name);
        eprintln!(
            "agent-firewall: agent session: {} (confidence {:.2}, {} signal(s))",
            agent.name,
            agent.confidence,
            agent.signals.len()
        );
    }
    // The B.5 facts: the monitor names itself, so a rule can ask whether a
    // signal goes to the firewall, and the sensor facts name the instances
    // the firewall itself runs with. Both travel inside the session start
    // event, so a replay answers the same questions from the trace.
    session.monitor_pid = std::process::id() as Pid;
    session.sensor = sensor_facts(&cwd);
    if let Some(sensor) = &session.sensor {
        eprintln!(
            "agent-firewall: in-process sensor active: {} instance(s) registered at start",
            sensor.instances.len()
        );
    }
    // The audit-trail fact of [af-9]: the trace file is a path the launcher
    // itself opened, so a write-open of it from a process of the session is
    // a fact of the firewall's own evidence — a B.5 fact in the shape of a
    // path, and never the basis of an allow. The sensor's trace and
    // registration paths ride the same rule inside the sensor facts.
    session.trace = args.trace.as_deref().map(|path| evidence_path(path, &cwd));

    let policy = load_policy(&args.policy).context("cannot load the rules")?;
    // A rule with a `threshold` block fires again on every action that
    // crosses the line, for as long as the window holds enough hits. The
    // handler collects those rule identifiers once, up front, so the
    // approval path can ask about such a rule one time for the session.
    let threshold_rules: BTreeSet<String> = policy
        .rules()
        .into_iter()
        .filter(|rule| rule.has_threshold)
        .map(|rule| rule.rule_id)
        .collect();
    let syscall_filter = parse_syscall_filter(&args.syscall_filter)?;
    let landlock = parse_landlock_mode(&args.landlock)?;
    let mode = approval_mode(&args)?;
    let approver = TerminalApprover::new(mode)
        .with_timeout(args.approval_timeout.map(std::time::Duration::from_secs));
    // A session that opts into telemetry keeps its own events in memory, so
    // the packaging at the end of the run needs no trace file. The handle is
    // shared with the fanout, which owns the writing end.
    let telemetry_sink = args.telemetry.then(SharedMemory::default);
    let sink = build_sink(&args, telemetry_sink.clone())?;

    let mut handler = FirewallHandler {
        memory: SessionMemory::with_baseline(session.baseline.clone()),
        session: session.clone(),
        graph: ProcessGraph::new(&session),
        policy: Box::new(policy),
        approver: Box::new(approver),
        sink,
        verbose: args.verbose,
        // Only a terminal prompt shows the explanation itself. In every other
        // mode the firewall must print the explanation, or a denied action
        // leaves no record for the user.
        explain_on_stderr: mode != ApprovalMode::Ask,
        interventions: 0,
        asked: 0,
        blocked: false,
        last_event_ts: session.started_at,
        exec_ts: None,
        answered: HashMap::new(),
        threshold_rules,
        pending_start: None,
        kernel_rules: BTreeSet::new(),
        kernel_denied: Vec::new(),
        pending_tamper: None,
    };

    let capabilities = Monitor::capabilities(syscall_filter);
    warn_about_missing_capabilities(&capabilities);
    // The `SessionStart` event waits for the identifier of the root process,
    // which only the monitor knows, because it launches that process itself.
    // The recorded metadata must carry the identifier: a rule with the scope
    // `subtree` reads it, and a replay of the trace has no other source for
    // it.
    handler.pending_start = Some(capabilities);

    let config = MonitorConfig {
        command: args.command.clone(),
        cwd: args.cwd.clone(),
        env_allowlist: Vec::new(),
        capture_input: !args.no_input_capture,
        syscall_filter,
        landlock,
        monitor_pid: session.monitor_pid,
        ..MonitorConfig::default()
    };

    let outcome = Monitor::run(&config, &session, &mut handler);
    // A session that never started still gets its start event, so a trace
    // always opens with the metadata of the session.
    handler.start_session();
    let outcome = outcome.context("the monitor failed")?;

    handler.emit(Event::new(
        session.session_id.clone(),
        0,
        EventKind::SessionEnd {
            exit_code: outcome.exit_code,
            process_count: handler.graph.len(),
        },
    ));

    if args.print_tree {
        eprintln!("\n{}", handler.graph.render_tree());
    }
    let blocked = handler.blocked || outcome.terminated_by_firewall;
    let interventions = handler.interventions;
    handler.sink.flush().ok();

    // The packaging runs after the session ended and after the trace is
    // flushed, adds no question and sends nothing: it writes local samples
    // when the consent file grants a scope, and says so when it does not.
    if let Some(shared) = telemetry_sink {
        let events = shared.events();
        crate::telemetry_cmds::finish_session(
            &args.telemetry_config,
            &args.telemetry_outbox,
            &events,
        );
    }

    if interventions > 0 {
        eprintln!(
            "agent-firewall: the session ended with {interventions} action(s) that needed a decision"
        );
    }

    if blocked {
        return Ok(EXIT_BLOCKED);
    }
    if let Some(code) = outcome.exit_code {
        return Ok(code);
    }
    if let Some(signal) = outcome.signal {
        return Ok(128 + signal);
    }
    Ok(0)
}

/// Reads the filter mode from a command-line value.
pub fn parse_syscall_filter(text: &str) -> Result<SyscallFilter> {
    match SyscallFilter::parse(text) {
        Some(filter) => Ok(filter),
        None => {
            bail!("`--syscall-filter` accepts write-only, all-opens or off, but it got `{text}`")
        }
    }
}

/// Reads the kernel-floor mode from a command-line value.
fn parse_landlock_mode(text: &str) -> Result<af_monitor::LandlockMode> {
    match af_monitor::LandlockMode::parse(text) {
        Some(mode) => Ok(mode),
        None => bail!("`--landlock` accepts on or off, but it got `{text}`"),
    }
}

/// Reads the approval mode from the command-line options.
fn approval_mode(args: &RunArgs) -> Result<ApprovalMode> {
    match args.approve.as_deref() {
        None => Ok(ApprovalMode::automatic()),
        Some(text) => match ApprovalMode::parse(text) {
            Some(mode) => Ok(mode),
            None => bail!("`--approve` accepts ask, allow or deny, but it got `{text}`"),
        },
    }
}

/// Makes the event sink from the command-line options.
///
/// `telemetry` is the shared memory sink of a session that opted in, or
/// `None`.
fn build_sink(args: &RunArgs, telemetry: Option<SharedMemory>) -> Result<Box<dyn EventSink>> {
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();
    if let Some(memory) = telemetry {
        sinks.push(Box::new(memory));
    }
    if let Some(path) = &args.trace {
        let retention = parse_retention(&args.retention)?;
        sinks.push(Box::new(
            TraceWriter::create(path, retention)
                .with_context(|| format!("cannot write the trace to {}", path.display()))?,
        ));
    }
    if args.json {
        sinks.push(Box::new(StreamSink::json(io::stdout())));
    } else if args.verbose {
        sinks.push(Box::new(StreamSink::human(io::stderr())));
    }
    Ok(Box::new(FanoutSink::with(sinks)))
}

/// Reads a retention mode from text.
fn parse_retention(text: &str) -> Result<Retention> {
    match text {
        "all" => Ok(Retention::All),
        "balanced" => Ok(Retention::Balanced),
        "evidence" | "evidence-only" => Ok(Retention::EvidenceOnly),
        other => bail!("`--retention` accepts all, balanced or evidence, but it got `{other}`"),
    }
}

/// Tells the user which protection this machine cannot give.
fn warn_about_missing_capabilities(capabilities: &[MonitorCapability]) {
    for capability in capabilities {
        if !capability.available && capability.name == "exec_interception" {
            eprintln!(
                "agent-firewall: warning: this machine cannot hold a program before it runs ({})",
                capability.detail.as_deref().unwrap_or("no detail")
            );
        }
    }
}

/// Holds every layer of the firewall during one session.
struct FirewallHandler {
    session: SessionMeta,
    graph: ProcessGraph,
    policy: Box<dyn PolicyEngine>,
    approver: Box<dyn af_core::Approver>,
    sink: Box<dyn EventSink>,
    verbose: bool,
    explain_on_stderr: bool,
    /// How many actions of the session needed a decision.
    ///
    /// The count holds every verdict that the firewall had to intervene on,
    /// also the ones that a remembered answer resolved without a question.
    /// The line at the end of the session counts decisions, not prompts.
    interventions: usize,
    /// How many times the session really asked somebody.
    ///
    /// A remembered answer does not raise this count. The two numbers differ
    /// exactly where the session repeated an earlier answer.
    asked: usize,
    blocked: bool,
    /// What the session remembers. The handler owns it and applies every
    /// effect that the engine asks for, in event order.
    memory: SessionMemory,
    /// Time of the newest event that the monitor produced.
    ///
    /// The memory keys on event time and never on a clock, so the replay of
    /// the trace of this session gives the same answers.
    last_event_ts: TimestampNanos,
    /// Time of the `ProcessExec` event of the process that waits at its stop.
    ///
    /// The firewall must judge an exec at the time of the exec itself. The
    /// monitor can emit another event between the exec event and the question
    /// to the handler — the content of standard input is one — and the replay
    /// of the trace judges the exec at the time of its own event. Without this
    /// field the live session would use the time of the later event and the
    /// two could differ.
    exec_ts: Option<(Pid, TimestampNanos)>,
    /// The answer that this session already gave for one held action.
    ///
    /// A refused call comes back. A program that gets `EPERM` from an open
    /// usually tries the same open again, or tries the next file of a list,
    /// and a firewall that asks the same question at every try is the thing
    /// that makes a user switch the firewall off. The key is the rule and the
    /// action, so a different file is still a new question.
    ///
    /// A rule with a `threshold` is the sharper case of the same problem: it
    /// fires again on every action that crosses the line, for as long as the
    /// window holds enough hits, and the action underneath is almost never
    /// the same twice. Such a rule keys on its identifier alone, so the
    /// session asks about it one time and repeats that answer for every
    /// later hit. See [`FirewallHandler::answer_key`].
    ///
    /// The approver has a memory of its own, but that one holds only what the
    /// user allowed **for the session**. A one-time answer and a refusal are
    /// not in it, and both have to hold here.
    answered: HashMap<String, Intercept>,
    /// Identifiers of every loaded rule that carries a `threshold` block.
    ///
    /// Built once, from `policy.rules()`, when the handler is made.
    threshold_rules: BTreeSet<String>,
    /// The rule classes the kernel floor enforces for this session.
    ///
    /// Filled from the `KernelFloor` event of the monitor. While it holds a
    /// rule, the kernel already answers that rule with a refusal: asking the
    /// user would offer a choice that no answer can make real, so the session
    /// explains instead of asking.
    kernel_rules: BTreeSet<String>,
    /// The path prefixes the kernel denies on a file open, with the rule
    /// class each answers.
    ///
    /// A rule that judges a file open rides on the floor only for a path
    /// under one of these prefixes: a credential store under the work tree or
    /// under `/tmp` is writable there, and its question stays a question.
    kernel_denied: Vec<(String, String)>,
    /// What the monitor can observe, until the session start event goes out.
    ///
    /// The event waits for the identifier of the root process. The value is
    /// `None` after the event went out, so the event goes out one time only.
    pending_start: Option<Vec<MonitorCapability>>,
    /// A sensed tamper fact that waits for its ruling.
    ///
    /// The graph raises the detachment flag of a descendant while the handler
    /// records an event, and no process waits at a stop at that moment. The
    /// handler parks the fact here, and the monitor takes it after the state
    /// change, suspends the tree and hands it to [`FirewallHandler::rule_tamper`].
    pending_tamper: Option<SensedTamper>,
}

impl FirewallHandler {
    /// Sends one event to the graph, to storage and to the identity ledger.
    ///
    /// The graph applies the event first, so the agent tag that the event
    /// carries reflects the state of the graph **after** the event: a
    /// descendant that detached from the tree keeps its tag and carries the
    /// unlinked flag on the very event that revealed the detachment.
    fn emit(&mut self, event: Event) {
        self.last_event_ts = event.ts;
        let pid = event.pid;
        if let EventKind::ProcessExec { process } = &event.kind {
            self.exec_ts = Some((process.pid, event.ts));
        }
        self.graph.apply(&event);
        let mut event = event;
        event.agent = self.graph.agent_tag(pid);
        if matches!(event.kind, EventKind::ProcessUnlinked { .. })
            && event
                .agent
                .as_ref()
                .is_some_and(|tag| tag.link == AgentLink::Unlinked)
        {
            eprintln!(
                "agent-firewall: process {pid} detached from the session tree; flagged unlinked"
            );
        }
        match &event.kind {
            EventKind::KernelFloor { rules, denied } => {
                self.kernel_rules = rules.iter().cloned().collect();
                self.kernel_denied = denied
                    .iter()
                    .map(|path| (path.prefix.clone(), path.rule.clone()))
                    .collect();
                eprintln!(
                    "agent-firewall: the kernel floor is active: {} rule class(es) enforced by \
                     the kernel, no approval can lift them (`--landlock off` starts without it)",
                    rules.len()
                );
            }
            EventKind::KernelDenied { rule, path } => match rule {
                Some(rule) => eprintln!(
                    "agent-firewall: the kernel denied opening {path}: rule {rule} is enforced \
                     by the kernel floor, and no approval can allow it in this session"
                ),
                None => eprintln!(
                    "agent-firewall: the kernel denied opening {path}: the floor grants no \
                     access there, and no approval can allow it in this session"
                ),
            },
            _ => {}
        }
        if let Err(error) = self.sink.record(&event) {
            eprintln!("agent-firewall: cannot record an event: {error}");
        }
        // The graph raises its unlink flags while it applies an event. Each
        // flag becomes one event of its own, which the same path records —
        // with the agent tag and the unlinked link state on it.
        for (unlinked_pid, detach) in self.graph.take_unlinked() {
            let process = self
                .graph
                .process(unlinked_pid)
                .unwrap_or_else(|| ProcessInfo::from_pid(unlinked_pid));
            self.emit(Event::new(
                self.session.session_id.clone(),
                unlinked_pid,
                EventKind::ProcessUnlinked {
                    process: Box::new(process),
                    detach,
                },
            ));
            // The detach is a sensed fact of the firewall's own tree, so a
            // rule judges it. The fact waits here because no process is held
            // at this moment; the monitor suspends the tree before the
            // ruling. Parking instead of asking keeps the recording path free
            // of any question, also for a session with no tamper rule.
            if self.pending_tamper.is_none() {
                self.pending_tamper = Some(SensedTamper {
                    kind: TamperKind::DetachedDescendant,
                    pid: unlinked_pid,
                    detail: format!(
                        "process {unlinked_pid} left the session tree (sid {}, root sid {})",
                        detach.sid, detach.root_sid
                    ),
                });
            }
        }
    }

    /// Writes the start of the session down, one time.
    ///
    /// The event carries the metadata with the identifier of the root
    /// process, so a replay of the trace reads the same session root as the
    /// live session did.
    fn start_session(&mut self) {
        let Some(capabilities) = self.pending_start.take() else {
            return;
        };
        self.emit(Event::new(
            self.session.session_id.clone(),
            self.session.root_pid,
            EventKind::SessionStart {
                meta: Box::new(self.session.clone()),
                capabilities,
            },
        ));
    }

    /// Builds the ancestry of a process, with a fallback for a gap in the graph.
    fn ancestry_of(&self, pid: Pid, fallback: &[Pid]) -> Vec<ProcessInfo> {
        let ancestry = self.graph.ancestry(pid);
        if !ancestry.is_empty() || fallback.is_empty() {
            return ancestry;
        }
        fallback
            .iter()
            .map(|p| {
                self.graph
                    .process(*p)
                    .unwrap_or_else(|| ProcessInfo::from_pid(*p))
            })
            .collect()
    }

    /// Returns the tamper facts that this exec carries, with the evidence
    /// line of each.
    ///
    /// Two facts can exist at an exec stop, and both are keyed to what the
    /// firewall itself did or installed:
    ///
    /// * the monitor killed the same program under the same parent earlier
    ///   in this session, and the parent started it again;
    /// * this session runs with the in-process sensor, and the environment
    ///   of the new program holds no copy of the sensor's preload.
    ///
    /// A session without a sensor can never raise the second fact, and a
    /// session where the firewall killed nothing can never raise the first —
    /// which is what keeps both inside the interruption budget.
    fn sensed_at_exec(&self, process: &ProcessInfo, sensed: &ExecSensed) -> Vec<SensedTamper> {
        let mut facts: Vec<SensedTamper> = Vec::new();
        if sensed.respawned_after_kill {
            let name = process
                .exe
                .as_deref()
                .map(Path::new)
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "the killed program".to_string());
            let parent = process
                .ppid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "an unknown parent".to_string());
            facts.push(SensedTamper {
                kind: TamperKind::KilledSubtreeReturned,
                pid: process.pid,
                detail: format!(
                    "{name} again under parent {parent}, after the firewall killed it in this session"
                ),
            });
        }
        if let Some(detail) = self.preload_stripped(process) {
            facts.push(SensedTamper {
                kind: TamperKind::PreloadStripped,
                pid: process.pid,
                detail,
            });
        }
        facts
    }

    /// Returns the evidence line when the new program inherits no copy of the
    /// sensor preload, and `None` otherwise.
    ///
    /// The question only exists for a session that runs with the in-process
    /// sensor — the launcher checked its own environment for it. A normal
    /// session carries no sensor, answers `None` at once, and can never
    /// raise the fact. A static binary keeps the variable in its environment
    /// even though the loader ignores it, so it stays quiet too: the fact is
    /// the removal of the configuration, not the ignorance of it.
    fn preload_stripped(&self, process: &ProcessInfo) -> Option<String> {
        let sensor = self.session.sensor.as_ref()?;
        let sensor_parts: Vec<&str> = sensor
            .preload
            .split(':')
            .filter(|part| !part.is_empty())
            .collect();
        let carries = process
            .env
            .get("LD_PRELOAD")
            .map(|value| value.split(':').any(|part| sensor_parts.contains(&part)))
            .unwrap_or(false);
        if carries {
            return None;
        }
        Some(format!(
            "the environment of the new program holds none of the {} sensor librar{} of this session",
            sensor_parts.len(),
            if sensor_parts.len() == 1 { "y" } else { "ies" },
        ))
    }

    /// Evaluates one action against the rules, with the session memory.
    ///
    /// The engine only reads the memory. It reports what it wants written,
    /// and the caller applies that in event order, so a replay of the trace
    /// reaches the same state.
    fn evaluate_one(
        &self,
        action: &Action,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        ts: TimestampNanos,
    ) -> (Verdict, Vec<MemoryEffect>) {
        self.policy.evaluate_with_memory(
            &EvalContext::new(&self.session, action, process, ancestry).at(ts),
            &self.memory,
        )
    }

    /// Evaluates every action that one exec produces.
    ///
    /// The new program is one action. Its standard input and its script are
    /// two more actions, because a dangerous statement often stays out of the
    /// command line.
    ///
    /// Every one of them is judged at `ts`, the time of the `ProcessExec`
    /// event, and the answers become one verdict. The replay of the trace
    /// folds the recorded standard input into the same exec in the same way,
    /// so both sides judge the same actions at the same time.
    fn evaluate(
        &self,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        input: Option<&InputSnapshot>,
        facts: &[SensedTamper],
        scan_script: bool,
        ts: TimestampNanos,
    ) -> (Action, Verdict, Vec<MemoryEffect>) {
        let exec_action = exec_action(process);
        let mut candidates: Vec<(Action, Verdict)> = Vec::new();
        let mut effects: Vec<MemoryEffect> = Vec::new();

        let (verdict, mut wanted) = self.evaluate_one(&exec_action, process, ancestry, ts);
        effects.append(&mut wanted);
        candidates.push((exec_action.clone(), verdict));

        // The tamper facts of this stop are actions of their own, judged with
        // the same memory at the same time, so a quarantine holds the program
        // before it runs.
        for fact in facts {
            let action = Action::Tamper {
                kind: fact.kind,
                detail: fact.detail.clone(),
            };
            let (verdict, mut wanted) = self.evaluate_one(&action, process, ancestry, ts);
            effects.append(&mut wanted);
            candidates.push((action, verdict));
        }

        if let Some(snapshot) = input {
            for (source, data) in [
                (af_core::InputSource::Stdin, snapshot.stdin.as_ref()),
                (
                    af_core::InputSource::File,
                    if scan_script {
                        snapshot.script.as_ref()
                    } else {
                        None
                    },
                ),
            ] {
                let Some(data) = data else { continue };
                if data.trim().is_empty() {
                    continue;
                }
                let action = Action::Input {
                    source,
                    data: data.clone(),
                };
                let (verdict, mut wanted) = self.evaluate_one(&action, process, ancestry, ts);
                effects.append(&mut wanted);
                candidates.push((action, verdict));
            }
        }

        let all_matches: Vec<_> = candidates
            .iter()
            .flat_map(|(_, verdict)| verdict.matches.iter().cloned())
            .collect();
        let combined = Verdict::from_matches(all_matches);

        let display_action = combined
            .top_match()
            .and_then(|top| {
                candidates
                    .iter()
                    .find(|(_, verdict)| verdict.matches.iter().any(|m| m.rule_id == top.rule_id))
                    .map(|(action, _)| action.clone())
            })
            .unwrap_or(exec_action);

        (display_action, combined, effects)
    }

    /// Runs the ruling over a quarantined session.
    ///
    /// The flow of `DIRECTION.md` §6: the tree stands still, the evidence is
    /// shown, the user rules — allow once, an exception for the session, or
    /// the end of the tree — and the trace holds every step of it like any
    /// policy decision. `tree` is `None` when the monitor already suspended
    /// the tree, which is the case for a fact that rose outside a held stop.
    fn quarantine(
        &mut self,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        action: &Action,
        verdict: &Verdict,
        mut tree: Option<&mut dyn TreeControl>,
    ) -> Intercept {
        let matched = verdict
            .matches
            .iter()
            .find(|matched| matched.quarantine)
            .or_else(|| verdict.top_match())
            .cloned();
        let rule_id = matched
            .as_ref()
            .map(|m| m.rule_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let evidence = match &matched {
            Some(m) => format!("{} — {}", action.summary(), m.title),
            None => action.summary(),
        };
        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::QuarantineStarted {
                rule: rule_id.clone(),
                evidence,
            },
        ));
        if let Some(tree) = tree.as_mut() {
            tree.suspend();
        }
        eprintln!("agent-firewall: quarantine: the session tree is suspended until the ruling");
        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::ApprovalRequested {
                action: Box::new(action.clone()),
                rule_id: rule_id.clone(),
            },
        ));
        let started = std::time::Instant::now();
        let outcome = {
            let request = ApprovalRequest {
                session: &self.session,
                action,
                process,
                ancestry,
                verdict,
            };
            self.approver.request(&request)
        };
        let waited_ms = started.elapsed().as_millis() as u64;
        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::ApprovalResolved {
                rule_id: rule_id.clone(),
                outcome,
                waited_ms,
            },
        ));
        if let Some(tree) = tree {
            match outcome {
                ApprovalOutcome::TerminateSession => {}
                _ => tree.resume(),
            }
        }
        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::QuarantineResolved {
                rule: rule_id,
                outcome,
            },
        ));
        match outcome {
            ApprovalOutcome::Allow | ApprovalOutcome::AllowForSession => Intercept::Continue,
            ApprovalOutcome::Deny => {
                self.blocked = true;
                // A quarantine sits on an action that a refusal can stop
                // completely: a signal that never runs, a program that never
                // starts. Deny keeps the same meaning it has everywhere else.
                Intercept::Refuse
            }
            ApprovalOutcome::TerminateSession => {
                self.blocked = true;
                Intercept::TerminateSession
            }
        }
    }

    /// Runs the ruling over a sensed tamper fact that rose outside a held
    /// stop.
    ///
    /// The monitor has already suspended the tree. The fact becomes an
    /// action, the rules judge it, and a verdict that needs a decision gets
    /// the quarantine of [`FirewallHandler::quarantine`]. A fact that no rule
    /// matches is still evidence: the tamper event and the decision are in
    /// the trace, and the session continues.
    fn judge_tamper(&mut self, sensed: SensedTamper) -> Intercept {
        let pid = sensed.pid;
        let process = self
            .graph
            .process(pid)
            .unwrap_or_else(|| ProcessInfo::from_pid(pid));
        let action = Action::Tamper {
            kind: sensed.kind,
            detail: sensed.detail.clone(),
        };
        self.emit(Event::new(
            self.session.session_id.clone(),
            pid,
            EventKind::Tamper {
                kind: sensed.kind,
                detail: sensed.detail,
            },
        ));
        let ancestry = self.ancestry_of(pid, &[]);
        let ts = self.last_event_ts;
        let (verdict, effects) = self.evaluate_one(&action, &process, &ancestry, ts);
        for effect in effects {
            self.memory.apply(effect, ts);
        }
        if !verdict.matches.is_empty() || self.verbose {
            self.emit(Event::new(
                self.session.session_id.clone(),
                pid,
                EventKind::PolicyDecision {
                    action: Box::new(action.clone()),
                    verdict: Box::new(verdict.clone()),
                    ancestry: ancestry.clone(),
                },
            ));
        }
        if !verdict.needs_intervention() {
            return Intercept::Continue;
        }
        if self.explain_on_stderr || verdict.decision != af_core::Decision::ApprovalRequired {
            eprintln!(
                "\n{}\n",
                display::explain(&ancestry, &process, &action, &verdict)
            );
        }
        self.asked += 1;
        if verdict.quarantine {
            return self.quarantine(&process, &ancestry, &action, &verdict, None);
        }
        match verdict.decision {
            af_core::Decision::Deny | af_core::Decision::Terminate => {
                self.blocked = true;
                Intercept::TerminateSession
            }
            _ => Intercept::Continue,
        }
    }

    /// Asks the user and turns the answer into an order for the monitor.
    fn ask(
        &mut self,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        action: &Action,
        verdict: &Verdict,
    ) -> Intercept {
        let rule_id = verdict
            .top_match()
            .map(|m| m.rule_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::ApprovalRequested {
                action: Box::new(action.clone()),
                rule_id: rule_id.clone(),
            },
        ));

        let started = std::time::Instant::now();
        let outcome = {
            let request = ApprovalRequest {
                session: &self.session,
                action,
                process,
                ancestry,
                verdict,
            };
            self.approver.request(&request)
        };
        let waited_ms = started.elapsed().as_millis() as u64;

        self.emit(Event::new(
            self.session.session_id.clone(),
            process.pid,
            EventKind::ApprovalResolved {
                rule_id,
                outcome,
                waited_ms,
            },
        ));

        match outcome {
            ApprovalOutcome::Allow | ApprovalOutcome::AllowForSession => Intercept::Continue,
            ApprovalOutcome::Deny => {
                self.blocked = true;
                Intercept::Deny
            }
            ApprovalOutcome::TerminateSession => {
                self.blocked = true;
                Intercept::TerminateSession
            }
        }
    }

    /// Returns the key under which the session remembers one answer, and
    /// whether that key holds a threshold rule.
    ///
    /// A rule with a `threshold` fires again on every action that crosses
    /// the line, for as long as the window holds enough hits, and the
    /// action underneath is almost never the same twice — a 500-file delete
    /// loop makes 500 different paths. Asking once per path would still be
    /// hundreds of prompts, so such a rule contributes its identifier alone:
    /// the session asks about it one time and repeats that answer for every
    /// later hit, whatever the action looks like.
    ///
    /// Every other rule contributes the narrower part: the same rule and the
    /// same kind of action can still return with different arguments, and
    /// each of those stays a new question.
    ///
    /// # Why every rule of the verdict is in the key
    ///
    /// The key must cover the **whole** reason that the firewall holds this
    /// action, and not only the strongest rule of it. A verdict that names a
    /// threshold rule and a second, different rule is a different question
    /// from the threshold rule alone. A key built from the top match alone
    /// would answer the second question with the answer that the user gave
    /// for the first one, and the user would never see the second rule. So
    /// every match that needs an intervention adds its own part, and the
    /// parts are sorted, because the order of the matches must not change the
    /// key.
    fn answer_key(&self, action: &Action, verdict: &Verdict) -> (String, bool) {
        let mut parts: Vec<String> = Vec::new();
        let mut has_threshold = false;
        for matched in &verdict.matches {
            if !matched.decision.needs_intervention() {
                continue;
            }
            if self.threshold_rules.contains(&matched.rule_id) {
                has_threshold = true;
                parts.push(matched.rule_id.clone());
            } else {
                parts.push(format!(
                    "{}|{}|{}",
                    matched.rule_id,
                    action.kind(),
                    action.summary()
                ));
            }
        }
        if parts.is_empty() {
            return (
                format!("no-rule|{}|{}", action.kind(), action.summary()),
                false,
            );
        }
        parts.sort();
        (parts.join(" + "), has_threshold)
    }

    /// Returns true when the kernel floor really refuses every action of
    /// this rule, so the session needs no answer from anybody.
    ///
    /// A rule that judges an **exec** rides on the floor when its class is in
    /// [`Self::kernel_rules`]: the classes there name trees the floor never
    /// grants, whatever the session. A rule that judges a **file open** needs
    /// the path on top: a rule about credential stores matches a `.ssh`
    /// under the work tree as well as the real one, and only the real one is
    /// hidden. The path comes from the seccomp stop and is advisory, and the
    /// worst case of a raced path is a question that the session did not ask
    /// while the kernel still decides on the real object — the refusal itself
    /// is never wrong, because the kernel makes it.
    fn kernel_answers(&self, rule_id: &str, action: &Action) -> bool {
        match action {
            Action::FileOpen { path, .. } => self
                .kernel_denied
                .iter()
                .any(|(prefix, rule)| rule == rule_id && path.starts_with(prefix.as_str())),
            _ => true,
        }
    }

    /// Resolves a verdict that needs a decision, and remembers the answer.
    ///
    /// This is where `on_exec` and `on_syscall` converge; [`Held`] carries
    /// what differs between the two stops.
    fn resolve(
        &mut self,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        action: &Action,
        verdict: &Verdict,
        held: Held<'_>,
    ) -> Intercept {
        // The kernel floor may already have answered this verdict. A rule
        // whose class the kernel enforces needs no question: the kernel
        // refuses the action whatever the user says, so asking would offer a
        // choice that no answer can make real. Only when **every** rule that
        // holds the action rides on the floor may the session stay quiet —
        // one rule that still needs a person keeps the whole question.
        let intervening: Vec<_> = verdict
            .matches
            .iter()
            .filter(|matched| matched.decision.needs_intervention())
            .collect();
        if !intervening.is_empty()
            && intervening.iter().all(|matched| {
                self.kernel_rules.contains(&matched.rule_id)
                    && self.kernel_answers(&matched.rule_id, action)
            })
        {
            for matched in &intervening {
                eprintln!(
                    "agent-firewall: the kernel floor enforces {} ({}): the action fails with \
                     EACCES and no approval can allow it in this session",
                    matched.rule_id, matched.title
                );
            }
            return Intercept::Continue;
        }
        let (key, is_threshold) = self.answer_key(action, verdict);
        let cached = held.caches || is_threshold;
        // Every held action is a decision of this session, whether the session
        // asked about it or repeated an earlier answer. The two counts are
        // separate, because "how many actions needed a decision" and "how many
        // times did the firewall ask" are two different numbers.
        self.interventions += 1;
        if cached {
            if let Some(answer) = self.answered.get(&key) {
                return *answer;
            }
        }

        self.asked += 1;
        if self.explain_on_stderr || verdict.decision != af_core::Decision::ApprovalRequired {
            eprintln!(
                "\n{}\n",
                display::explain(ancestry, process, action, verdict)
            );
        }
        // A rule that asks for a quarantine gets one: the tree stands still
        // while the user reads the evidence and rules. One question, one
        // ruling, and the whole exchange is in the trace like any policy
        // decision. A remembered answer never suspends anything — the ruling
        // was taken, and the session repeats it.
        if verdict.quarantine {
            let answer = self.quarantine(process, ancestry, action, verdict, Some(held.tree));
            if cached {
                self.answered.insert(key, answer);
            }
            return answer;
        }
        let answer = match verdict.decision {
            af_core::Decision::Deny => {
                self.blocked = true;
                held.deny
            }
            af_core::Decision::Terminate => {
                self.blocked = true;
                Intercept::TerminateSession
            }
            _ => match self.ask(process, ancestry, action, verdict) {
                Intercept::Deny => held.deny,
                other => other,
            },
        };
        if cached {
            self.answered.insert(key, answer);
        }
        answer
    }
}

/// What differs between the two stops that wait for a decision.
///
/// `deny` is the intercept that a `Decision::Deny` verdict, and a user's
/// refusal, produce at the stop — an exec holds the exec itself, so it
/// answers `Intercept::Deny`; a system call has not happened yet, so it
/// answers `Intercept::Refuse`. `caches` says whether a non-threshold match
/// may reuse the answer of the session: a refused call comes back and would
/// otherwise ask the same question again, while two different exec actions
/// are two different questions. `tree` carries the orders of a quarantine.
struct Held<'a> {
    deny: Intercept,
    caches: bool,
    tree: &'a mut dyn TreeControl,
}

impl MonitorHandler for FirewallHandler {
    fn on_event(&mut self, event: Event) {
        self.emit(event);
    }

    fn on_session_root(&mut self, root: Pid) {
        // The root of the session is the process that the monitor launched.
        // Every subtree of the session hangs directly under it, so a rule with
        // the scope `subtree` needs this identifier, and so does the graph.
        self.session.root_pid = root;
        self.start_session();
    }

    fn take_tamper(&mut self) -> Option<SensedTamper> {
        self.pending_tamper.take()
    }

    fn rule_tamper(&mut self, sensed: SensedTamper) -> Intercept {
        self.judge_tamper(sensed)
    }

    fn on_exec(
        &mut self,
        process: &ProcessInfo,
        ancestry_pids: &[Pid],
        input: Option<&InputSnapshot>,
        sensed: &ExecSensed,
        tree: &mut dyn TreeControl,
    ) -> Intercept {
        // The recorded event keeps the true facts of the process. The policy
        // engine judges the program that the process really runs, which is
        // the script when an interpreter runs a wrapper script.
        let judged = normalize::for_policy(process);
        // A shell script needs no content scan. Every command of the script
        // becomes its own exec event, and the firewall judges that event with
        // its full provenance. A scan of the text would stop the shell before
        // it reaches the command, and it would report a command that the
        // script can skip. The test must read the true interpreter, because
        // the judged facts name the script and not the shell.
        let scan_script = !normalize::is_shell(process.program_name());
        // The sensed facts of this stop become events first — the trace holds
        // the attempt whatever the rules say — and actions right after, so a
        // quarantine can hold this program before it runs.
        let facts = self.sensed_at_exec(&judged, sensed);
        for fact in &facts {
            self.emit(Event::new(
                self.session.session_id.clone(),
                process.pid,
                EventKind::Tamper {
                    kind: fact.kind,
                    detail: fact.detail.clone(),
                },
            ));
        }
        let ancestry = self.ancestry_of(process.pid, ancestry_pids);
        // The exec is judged at the time of its own event, and never at the
        // time of the newest event. The monitor emits the content of standard
        // input after the exec event, and a replay judges the exec at the time
        // that the exec event carries.
        let ts = match self.exec_ts.take() {
            Some((pid, ts)) if pid == process.pid => ts,
            _ => self.last_event_ts,
        };
        let (action, verdict, effects) =
            self.evaluate(&judged, &ancestry, input, &facts, scan_script, ts);
        // The engine only reads the memory. The handler writes it, in event
        // order, so the replay of this trace reaches the same state.
        for effect in effects {
            self.memory.apply(effect, ts);
        }

        if !verdict.matches.is_empty() || self.verbose {
            self.emit(Event::new(
                self.session.session_id.clone(),
                process.pid,
                EventKind::PolicyDecision {
                    action: Box::new(action.clone()),
                    verdict: Box::new(verdict.clone()),
                    ancestry: ancestry.clone(),
                },
            ));
        }

        if !verdict.needs_intervention() {
            return Intercept::Continue;
        }

        // Only a threshold match is cached here. Two different exec actions
        // are two different questions, so the caller keeps asking about them
        // — but a threshold rule fires again and again for a burst that is
        // really one event, and the session answers that one time.
        self.resolve(
            &judged,
            &ancestry,
            &action,
            &verdict,
            Held {
                deny: Intercept::Deny,
                caches: false,
                tree,
            },
        )
    }

    fn on_syscall(
        &mut self,
        pid: Pid,
        action: &Action,
        ancestry_pids: &[Pid],
        tree: &mut dyn TreeControl,
    ) -> Intercept {
        // The process is already known from its exec event, so the handler
        // reads it from the graph instead of asking `/proc` again. A session
        // makes many of these stops and every one of them holds a process.
        let process = self
            .graph
            .process(pid)
            .unwrap_or_else(|| ProcessInfo::from_pid(pid));
        let ancestry = self.ancestry_of(pid, ancestry_pids);

        // The event of the held call is the newest event, because the monitor
        // emits it directly before it asks the handler.
        let ts = self.last_event_ts;
        let (verdict, effects) = self.evaluate_one(action, &process, &ancestry, ts);
        for effect in effects {
            self.memory.apply(effect, ts);
        }

        if !verdict.matches.is_empty() || self.verbose {
            self.emit(Event::new(
                self.session.session_id.clone(),
                pid,
                EventKind::PolicyDecision {
                    action: Box::new(action.clone()),
                    verdict: Box::new(verdict.clone()),
                    ancestry: ancestry.clone(),
                },
            ));
        }

        if !verdict.needs_intervention() {
            return Intercept::Continue;
        }

        // A refused call comes back, so the same question would come back
        // with it. The session answers it one time. A file open and a
        // connection have not happened yet, so letting the call fail stops
        // the action completely. The program then gets an ordinary
        // permission error and can say so in its own words, which `SIGKILL`
        // would take away from it.
        self.resolve(
            &process,
            &ancestry,
            action,
            &verdict,
            Held {
                deny: Intercept::Refuse,
                caches: true,
                tree,
            },
        )
    }
}

/// Assesses the root command of the session with the built-in detectors.
///
/// Returns the identified agent when the combined confidence crossed the
/// tagging threshold, and `None` otherwise. The function reads the facts one
/// time, at launch: the resolved program, the command line, the working
/// directory, the environment the root inherits, and the dependency
/// manifests of the working directory. Nothing it reads reaches the trace
/// except the signals that matched.
fn detect_agent_root(command: &[String], cwd: &Path) -> Option<af_core::IdentifiedAgent> {
    let registry = DetectorRegistry::with_builtin_detectors();
    let input = DetectionInput {
        exe: command
            .first()
            .and_then(|program| resolve_program(program, cwd)),
        argv: command.to_vec(),
        cwd: cwd.display().to_string(),
        env: std::env::vars().collect(),
        manifest_dependencies: manifest_dependencies(cwd),
    };
    registry.assess(&input).agent
}

/// Resolves a program name of the command line to its full path.
///
/// A name with a slash resolves against the working directory. A bare name
/// walks the `PATH` of the launcher, and the first executable match wins.
/// The resolved path carries the installation metadata that the install
/// detector reads — an executable under `node_modules/@anthropic-ai/
/// claude-code` names its package whatever its program name is.
fn resolve_program(program: &str, cwd: &Path) -> Option<String> {
    let candidate = Path::new(program);
    let direct = if candidate.is_absolute() {
        Some(candidate.to_path_buf())
    } else if program.contains('/') {
        Some(cwd.join(candidate))
    } else {
        None
    };
    if let Some(path) = direct {
        return path
            .canonicalize()
            .ok()
            .map(|resolved| resolved.display().to_string());
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join(program);
        if is_executable_file(&full) {
            return full
                .canonicalize()
                .ok()
                .map(|resolved| resolved.display().to_string());
        }
    }
    None
}

/// Returns true when this path is a file the launcher may execute.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Reads the dependency names that the `package.json` of the working
/// directory carries.
///
/// A dependency manifest is supporting evidence and never a tag on its own:
/// a project that develops with an agent depends on its package, and a build
/// in that project is a normal dev session. The function reads the one
/// manifest that npm-shaped toolchains leave at the root of a work tree, and
/// nothing else, and it runs one time for each session.
fn manifest_dependencies(cwd: &Path) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    let Ok(text) = std::fs::read_to_string(cwd.join("package.json")) else {
        return names;
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&text) else {
        return names;
    };
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(entries) = manifest.get(section).and_then(|value| value.as_object()) {
            for name in entries.keys() {
                names.insert(name.clone());
            }
        }
    }
    names
}

/// Reads the git remotes of a directory, as names and as addresses.
///
/// The launcher records the answer at session start. A rule can then see that
/// a push goes to a remote that did not exist when the work began, which is
/// the shape of the Shai-Hulud supply-chain attack.
///
/// A directory that is not a repository, and a repository with no remote,
/// both give an empty set. The command runs one time for each session.
fn git_remotes(cwd: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["config", "--get-regexp", r"^remote\..*\.url$"])
        .output();
    let Ok(output) = output else {
        return out;
    };
    if !output.status.success() {
        return out;
    }
    let Ok(text) = String::from_utf8(output.stdout) else {
        return out;
    };
    for line in text.lines() {
        let Some((key, url)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = key
            .strip_prefix("remote.")
            .and_then(|rest| rest.strip_suffix(".url"));
        if let Some(name) = name {
            if !name.is_empty() {
                out.insert(name.to_string());
            }
        }
        let url = url.trim();
        if !url.is_empty() {
            out.insert(url.to_string());
        }
    }
    out
}

/// Reads what the launcher knows about the in-process sensor of this run.
///
/// The sensor of `research/spikes/inprocess/` is a research instrument that
/// the caller installs through the environment, so the launcher reads its own
/// environment to learn whether a session runs with one: the `LD_PRELOAD`
/// that carried the shim in, the registration record the shim appends to,
/// and the trace file the shim writes. The launcher takes one snapshot at
/// start; whether an instance still speaks is the correlation question of a
/// later milestone.
///
/// A run with no sensor returns `None`, and every rule that keys on sensor
/// instances then answers nothing — the quiet, correct answer for a normal
/// session.
fn sensor_facts(cwd: &Path) -> Option<SensorMeta> {
    let preload = std::env::var("LD_PRELOAD").ok()?;
    if !preload.split(':').any(|path| {
        Path::new(path)
            .file_name()
            .is_some_and(|name| name == "libafsensor.so")
    }) {
        return None;
    }
    let registration_path = std::env::var_os("AF_SENSOR_REG").map(PathBuf::from);
    let instances = registration_path
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| sensor_instances(&text))
        .unwrap_or_default();
    Some(SensorMeta {
        preload,
        instances,
        trace: env_evidence_path("AF_SENSOR_TRACE", cwd),
        registration: registration_path
            .as_deref()
            .map(|path| evidence_path(path, cwd)),
    })
}

/// Reads an environment name as an evidence path of the sensor.
///
/// The sensor writes its facts as paths relative to the directory the
/// launcher ran in, so the answer is the absolute, lexically clean form.
fn env_evidence_path(name: &str, cwd: &Path) -> Option<String> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .map(|path| evidence_path(&path, cwd))
}

/// Makes the absolute, lexically clean form of a path.
///
/// The monitor records the path of an open stop in exactly this form —
/// absolute, with no `.` and `..` parts and no doubled separators — so the
/// audit-trail facts and the observed path of a write-open compare equal
/// without asking the file system. The trace file does not exist yet when
/// the launcher names it, which is why the cleanup is lexical and not a
/// canonicalize: a symlink on the way changes nothing here, and a path that
/// reaches the file through another shape is a gap that the facts honestly
/// do not cover.
fn evidence_path(path: &Path, cwd: &Path) -> String {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for part in joined.iter() {
        match part.to_str() {
            Some(".") => {}
            Some("..") => {
                parts.pop();
            }
            _ => parts.push(part.to_os_string()),
        }
    }
    let mut out = PathBuf::from("/");
    out.extend(parts);
    out.display().to_string()
}

/// Reads the process identifiers out of a registration record.
///
/// The record of the research sensor holds one JSON object per line, and a
/// line of type `sensor_register` names a live instance in its `pid` field,
/// while a line of type `sensor_exit` ends one. The reader keeps the order
/// of the file, so the last word about a process wins. A line that is not
/// valid JSON is not from the sensor, and the reader skips it.
fn sensor_instances(record: &str) -> Vec<Pid> {
    let mut live: Vec<Pid> = Vec::new();
    for line in record.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(pid) = value
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .and_then(|pid| pid.try_into().ok())
        else {
            continue;
        };
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("sensor_register") => {
                if !live.contains(&pid) {
                    live.push(pid);
                }
            }
            Some("sensor_exit") => live.retain(|live| *live != pid),
            _ => {}
        }
    }
    live
}

/// Makes an exec action from the facts of a process.
fn exec_action(process: &ProcessInfo) -> Action {
    Action::Exec {
        exe: process.exe.clone(),
        program: process.program_name().to_string(),
        argv: process.argv.clone(),
        cwd: process.cwd.clone(),
        env: process.env.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use af_approval::ScriptedApprover;
    use af_policy::PolicySet;

    /// A tree control that records nothing and orders nothing, for the tests
    /// of the decision path.
    struct NoTree;

    impl TreeControl for NoTree {
        fn suspend(&mut self) {}
        fn resume(&mut self) {}
    }

    /// A sink that keeps every event it receives, for a test to inspect.
    ///
    /// [`FirewallHandler::sink`] is a `Box<dyn EventSink>`, so a test cannot
    /// read the concrete sink back out of the handler. This sink shares its
    /// list with the test through an [`Arc`], instead. `EventSink` needs
    /// `Send`, which rules out the simpler `Rc<RefCell<_>>`.
    #[derive(Default)]
    struct RecordingSink(Arc<Mutex<Vec<Event>>>);

    impl EventSink for RecordingSink {
        fn record(&mut self, event: &Event) -> af_core::Result<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    /// A rule with a `threshold` block: the shape of `memory.filesystem.delete-burst`.
    const THRESHOLD_POLICY: &str = "
version: 1
name: test.threshold
description: A rule with a threshold, for the one-ask test.
rules:
  - id: test.threshold.delete-burst
    title: Test delete burst
    category: test
    risk: approval_required
    decision: approval_required
    reason: A burst of deletes ran.
    match:
      action: exec
      program: [rm]
    threshold:
      window_seconds: 60
      at_least: 2
";

    /// A threshold rule and a second, sharper rule that can match with it.
    ///
    /// The identifier of the threshold rule sorts first, so it also wins the
    /// tie between two rules of the same level and becomes the top match.
    /// That is exactly the shape in which a second rule can hide behind a
    /// remembered answer.
    const TWO_RULE_POLICY: &str = "
version: 1
name: test.two
description: A threshold rule and a second rule that can match the same action.
rules:
  - id: test.a-delete-burst
    title: Test delete burst
    category: test
    risk: approval_required
    decision: approval_required
    reason: A burst of deletes ran.
    match:
      action: exec
      program: [rm]
    threshold:
      window_seconds: 60
      at_least: 2
  - id: test.b-state-wipe
    title: Test delete of the state of the agent
    category: test
    risk: approval_required
    decision: approval_required
    reason: The command removes the state of the agent itself.
    match:
      action: exec
      program: [rm]
      argv_matches: '\\.agent-state'
";

    /// A rule with no `threshold` block, for comparison.
    const PLAIN_POLICY: &str = "
version: 1
name: test.plain
description: A rule with no threshold, for the re-ask test.
rules:
  - id: test.plain.file-open
    title: Test file open
    category: test
    risk: approval_required
    decision: approval_required
    reason: A file was opened.
    match:
      action: file_open
";

    /// Two rules with no threshold that match the same file open.
    const PAIR_POLICY: &str = "
version: 1
name: test.pair
description: Two rules that hold the same action, for the one-question test.
rules:
  - id: test.pair.file-open
    title: Test file open
    category: test
    risk: approval_required
    decision: approval_required
    reason: A file was opened.
    match:
      action: file_open
  - id: test.pair.credential-open
    title: Test credential open
    category: test
    risk: approval_required
    decision: approval_required
    reason: A credential store was opened.
    match:
      action: file_open
      path_matches: 'credentials'
";

    /// Builds a handler the same way `run` does, with a scripted approver.
    ///
    /// Returns the handler together with the list of events it records, so a
    /// test can check that a silently repeated answer still leaves an honest
    /// trail.
    fn handler_for(
        policy: &str,
        answers: Vec<ApprovalOutcome>,
    ) -> (FirewallHandler, Arc<Mutex<Vec<Event>>>) {
        let policy = PolicySet::from_str(policy, "test").expect("the test policy must load");
        let threshold_rules: BTreeSet<String> = policy
            .rules()
            .into_iter()
            .filter(|rule| rule.has_threshold)
            .map(|rule| rule.rule_id)
            .collect();
        let session = SessionMeta::new(vec!["test".to_string()], "/home/dev/app".to_string());
        let events = Arc::new(Mutex::new(Vec::new()));
        let handler = FirewallHandler {
            memory: SessionMemory::with_baseline(session.baseline.clone()),
            graph: ProcessGraph::new(&session),
            last_event_ts: session.started_at,
            session,
            policy: Box::new(policy),
            approver: Box::new(ScriptedApprover::new(answers)),
            sink: Box::new(RecordingSink(events.clone())),
            verbose: false,
            explain_on_stderr: false,
            interventions: 0,
            asked: 0,
            blocked: false,
            exec_ts: None,
            answered: HashMap::new(),
            threshold_rules,
            pending_start: None,
            kernel_rules: BTreeSet::new(),
            kernel_denied: Vec::new(),
            pending_tamper: None,
        };
        (handler, events)
    }

    /// Returns a process that runs `rm` on a path that no other call uses.
    fn rm_process(pid: Pid, suffix: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(200),
            exe: Some("/usr/bin/rm".to_string()),
            comm: "rm".to_string(),
            argv: vec![
                "rm".to_string(),
                "-f".to_string(),
                format!("build/tmp-{suffix}.o"),
            ],
            cwd: Some("/home/dev/app".to_string()),
            ..ProcessInfo::default()
        }
    }

    #[test]
    fn a_threshold_rule_asks_one_time_for_the_session() {
        let (mut handler, _events) = handler_for(THRESHOLD_POLICY, vec![ApprovalOutcome::Allow]);

        // The first delete does not reach the threshold, so it stays quiet
        // and asks nobody.
        let first = handler.on_exec(
            &rm_process(400, "a"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        assert_eq!(first, Intercept::Continue);
        assert_eq!(handler.interventions, 0);
        assert_eq!(handler.asked, 0);

        // The rule fires on the next three deletes, each with a different
        // path, exactly like a runaway loop. The session must ask about it
        // one time and repeat that answer for the other two fires.
        for (offset, suffix) in ["b", "c", "d"].into_iter().enumerate() {
            let outcome = handler.on_exec(
                &rm_process(401 + offset as i32, suffix),
                &[],
                None,
                &ExecSensed::default(),
                &mut NoTree,
            );
            assert_eq!(
                outcome,
                Intercept::Continue,
                "fire {offset} must repeat the session's answer"
            );
        }

        assert_eq!(
            handler.asked, 1,
            "a threshold rule must ask about the session one time, however many times it fires"
        );
        assert_eq!(
            handler.interventions, 3,
            "every fire is still an action that needed a decision, also the ones that repeated the answer"
        );
    }

    #[test]
    fn a_threshold_rule_remembers_a_refusal_too() {
        let (mut handler, _events) = handler_for(THRESHOLD_POLICY, vec![ApprovalOutcome::Deny]);

        let first = handler.on_exec(
            &rm_process(400, "a"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        let second = handler.on_exec(
            &rm_process(401, "b"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        let third = handler.on_exec(
            &rm_process(402, "c"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );

        assert_eq!(
            first,
            Intercept::Continue,
            "the first delete is below the threshold"
        );
        assert_eq!(
            second,
            Intercept::Deny,
            "the burst is refused once it fires"
        );
        assert_eq!(
            third,
            Intercept::Deny,
            "a refusal must stick for the rest of the session, not just an allow"
        );
        assert_eq!(handler.asked, 1, "the session asks one time");
        assert_eq!(
            handler.interventions, 2,
            "both fires needed a decision, whether or not the session asked again"
        );
    }

    #[test]
    fn a_threshold_rule_still_records_every_decision_honestly() {
        let (mut handler, events) = handler_for(THRESHOLD_POLICY, vec![ApprovalOutcome::Allow]);

        // The first delete stays below the threshold and matches no rule.
        handler.on_exec(
            &rm_process(400, "a"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        // The next two fire. The second one repeats the session's answer
        // silently, but the decision itself must still leave a trace.
        handler.on_exec(
            &rm_process(401, "b"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        handler.on_exec(
            &rm_process(402, "c"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );

        let events = events.lock().unwrap();
        let policy_decisions = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::PolicyDecision { .. }))
            .count();
        let approval_requested = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::ApprovalRequested { .. }))
            .count();
        let approval_resolved = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::ApprovalResolved { .. }))
            .count();

        assert_eq!(
            policy_decisions, 2,
            "both fires must record a policy decision, whether or not the session asked:\n{events:#?}"
        );
        assert_eq!(
            approval_requested, 1,
            "the user is asked only for the first fire:\n{events:#?}"
        );
        assert_eq!(
            approval_resolved, 1,
            "the resolved event follows the one question that was asked:\n{events:#?}"
        );
    }

    /// A remembered answer must never answer a question that nobody asked.
    ///
    /// The session answers the burst one time. When a later delete matches
    /// the burst **and** a second rule, the question is a different one: the
    /// user has said nothing about that second rule. The firewall must ask
    /// again, and the answer of the burst must not be given for it.
    #[test]
    fn a_second_rule_in_the_verdict_asks_again() {
        let (mut handler, events) = handler_for(
            TWO_RULE_POLICY,
            vec![ApprovalOutcome::Allow, ApprovalOutcome::Deny],
        );

        // Two ordinary deletes. The second crosses the threshold and the
        // session answers it one time.
        handler.on_exec(
            &rm_process(400, "a"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        handler.on_exec(
            &rm_process(401, "b"),
            &[],
            None,
            &ExecSensed::default(),
            &mut NoTree,
        );
        assert_eq!(handler.asked, 1, "the burst is one question");

        // The third delete removes the state of the agent, so the sharper
        // rule matches with the burst rule. The user has never seen that
        // rule.
        let mut wipe = rm_process(402, "c");
        wipe.argv = vec![
            "rm".to_string(),
            "-rf".to_string(),
            "/home/dev/.agent-state".to_string(),
        ];
        let answer = handler.on_exec(&wipe, &[], None, &ExecSensed::default(), &mut NoTree);

        assert_eq!(
            handler.asked, 2,
            "a rule that the user has not answered must bring its own question"
        );
        assert_eq!(
            answer,
            Intercept::Deny,
            "the second question gets its own answer, and here that answer is no"
        );

        // The question that went out must name the rule that is new.
        let events = events.lock().unwrap();
        let named = events.iter().any(|event| match &event.kind {
            EventKind::PolicyDecision { verdict, .. } => verdict
                .matches
                .iter()
                .any(|m| m.rule_id == "test.b-state-wipe"),
            _ => false,
        });
        assert!(named, "the decision must record the new rule:\n{events:#?}");
        let explanation = display::explain(
            &[],
            &wipe,
            &exec_action(&wipe),
            &Verdict::from_matches(vec![
                af_core::RuleMatch {
                    rule_id: "test.a-delete-burst".to_string(),
                    title: "Test delete burst".to_string(),
                    category: "test".to_string(),
                    risk: af_core::RiskLevel::ApprovalRequired,
                    decision: af_core::Decision::ApprovalRequired,
                    quarantine: false,
                    reason: "A burst of deletes ran.".to_string(),
                },
                af_core::RuleMatch {
                    rule_id: "test.b-state-wipe".to_string(),
                    title: "Test delete of the state of the agent".to_string(),
                    category: "test".to_string(),
                    risk: af_core::RiskLevel::ApprovalRequired,
                    decision: af_core::Decision::ApprovalRequired,
                    quarantine: false,
                    reason: "The command removes the state of the agent itself.".to_string(),
                },
            ]),
        );
        assert!(
            explanation.contains("test.b-state-wipe"),
            "the text that the user reads must name every rule that holds the action:\n{explanation}"
        );
    }

    /// The same pair of rules twice is still one question.
    #[test]
    fn the_same_pair_of_rules_repeats_its_answer() {
        let (mut handler, _events) = handler_for(
            PAIR_POLICY,
            vec![ApprovalOutcome::Allow, ApprovalOutcome::Allow],
        );

        let open = Action::FileOpen {
            path: "/home/dev/.aws/credentials".to_string(),
            write: false,
        };
        handler.on_syscall(500, &open, &[], &mut NoTree);
        handler.on_syscall(500, &open, &[], &mut NoTree);
        assert_eq!(
            handler.asked, 1,
            "the same rules and the same action stay one question"
        );
    }

    #[test]
    fn a_non_threshold_rule_still_re_asks_for_a_different_summary() {
        let (mut handler, _events) = handler_for(
            PLAIN_POLICY,
            vec![ApprovalOutcome::Allow, ApprovalOutcome::Allow],
        );

        let first = handler.on_syscall(
            500,
            &Action::FileOpen {
                path: "/home/dev/.aws/credentials".to_string(),
                write: false,
            },
            &[],
            &mut NoTree,
        );
        let second = handler.on_syscall(
            500,
            &Action::FileOpen {
                path: "/home/dev/.ssh/id_ed25519".to_string(),
                write: false,
            },
            &[],
            &mut NoTree,
        );

        assert_eq!(first, Intercept::Continue);
        assert_eq!(second, Intercept::Continue);
        assert_eq!(
            handler.asked, 2,
            "a rule with no threshold must still ask about a different path"
        );
        assert_eq!(handler.interventions, 2);
    }

    #[test]
    fn a_non_threshold_rule_still_caches_the_same_summary() {
        let (mut handler, _events) = handler_for(
            PLAIN_POLICY,
            vec![ApprovalOutcome::Allow, ApprovalOutcome::Deny],
        );

        let action = Action::FileOpen {
            path: "/home/dev/.aws/credentials".to_string(),
            write: false,
        };
        let first = handler.on_syscall(500, &action, &[], &mut NoTree);
        let second = handler.on_syscall(500, &action, &[], &mut NoTree);

        assert_eq!(first, Intercept::Continue);
        assert_eq!(
            second, first,
            "the same rule and the same summary must repeat the first answer, exactly as before this change"
        );
        assert_eq!(handler.asked, 1, "the session asks one time");
        assert_eq!(
            handler.interventions, 2,
            "both opens needed a decision, and the count of decisions says so"
        );
    }

    // ------------------------------------------------------------------
    // The tamper facts and the quarantine flow of M4.
    // ------------------------------------------------------------------

    /// A rule that quarantines, in the shape of `policies/tamper.yaml`.
    const QUARANTINE_POLICY: &str = "
version: 1
name: test.quarantine
description: A rule that suspends the tree, for the ruling test.
rules:
  - id: test.tamper.quarantine
    title: Test quarantine
    category: test
    risk: approval_required
    decision: approval_required
    quarantine: true
    reason: The rule asks for a quarantine.
    match:
      action: signal_send
      signal_target: [monitor]
    tests:
      - name: a signal to the monitor quarantines
        expect: approval_required
        monitor_pid: 900
        process: { pid: 100, comm: payload, argv: [payload] }
        ancestry: [{ pid: 50, comm: bash }]
        signal_send: { target: 900, signal: 9 }
      - name: a signal to another process stays quiet
        expect: allow
        monitor_pid: 900
        process: { pid: 100, comm: payload, argv: [payload] }
        ancestry: [{ pid: 50, comm: bash }]
        signal_send: { target: 4321, signal: 15 }
";

    /// A tree control that remembers the orders it carried out.
    #[derive(Default)]
    struct RecordingTree {
        suspended: usize,
        resumed: usize,
    }

    impl TreeControl for RecordingTree {
        fn suspend(&mut self) {
            self.suspended += 1;
        }
        fn resume(&mut self) {
            self.resumed += 1;
        }
    }

    #[test]
    fn a_quarantine_rule_suspends_the_tree_once_and_takes_one_ruling() {
        let (mut handler, events) = handler_for(
            QUARANTINE_POLICY,
            vec![ApprovalOutcome::Allow, ApprovalOutcome::Deny],
        );
        // The B.5 fact: the session names its monitor.
        handler.session.monitor_pid = 900;
        let mut tree = RecordingTree::default();

        let signal = Action::SignalSend {
            target: 900,
            signal: 9,
        };
        let first = handler.on_syscall(100, &signal, &[50], &mut tree);
        let second = handler.on_syscall(100, &signal, &[50], &mut tree);

        assert_eq!(
            first,
            Intercept::Continue,
            "the allow of the ruling lets the call run"
        );
        assert_eq!(handler.asked, 1, "one ruling, one question");
        assert_eq!(
            tree.suspended, 1,
            "the tree stands still exactly while the user rules"
        );
        assert_eq!(tree.resumed, 1, "the tree runs again after the ruling");
        // A repeated fact repeats the ruling without asking and without
        // suspending anything: the answer of the session holds.
        assert_eq!(
            second,
            Intercept::Continue,
            "the ruling of the session is the answer of every later fire"
        );
        assert_eq!(handler.asked, 1, "the answer of the session holds");
        assert_eq!(tree.suspended, 1);

        let events = events.lock().unwrap();
        let kinds: Vec<&str> = events.iter().map(|e| e.kind_label()).collect();
        // The monitor writes the `signal_send` event before it calls the
        // handler, so the trace of a live session opens with it; this test
        // drives the handler directly and sees the exchange itself.
        assert_eq!(
            kinds,
            vec![
                "policy_decision",
                "quarantine_started",
                "approval_requested",
                "approval_resolved",
                "quarantine_resolved",
                "policy_decision",
            ],
            "the whole exchange is in the trace like any policy decision:\n{events:#?}"
        );
    }

    #[test]
    fn a_signal_to_another_process_never_wakes_the_quarantine() {
        let (mut handler, events) = handler_for(QUARANTINE_POLICY, vec![]);
        handler.session.monitor_pid = 900;
        let mut tree = RecordingTree::default();

        let other = Action::SignalSend {
            target: 4321,
            signal: 15,
        };
        let answer = handler.on_syscall(100, &other, &[50], &mut tree);

        assert_eq!(answer, Intercept::Continue);
        assert_eq!(handler.asked, 0, "the rule stays quiet");
        assert_eq!(tree.suspended, 0);
        let events = events.lock().unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.kind_label() != "quarantine_started"),
            "no quarantine on a signal the rule does not key on"
        );
    }

    #[test]
    fn the_sensor_registration_record_names_the_live_instances() {
        let record = "\
{\"type\":\"sensor_register\",\"instance\":\"a\",\"pid\":100,\"ppid\":1,\"exe\":\"/bin/sh\",\"session\":\"s\",\"ts\":1}
{\"type\":\"sensor_register\",\"instance\":\"b\",\"pid\":200,\"ppid\":100,\"exe\":\"/bin/sh\",\"session\":\"s\",\"ts\":2}
{\"type\":\"sensor_heartbeat\",\"instance\":\"a\",\"pid\":100,\"ppid\":1,\"exe\":\"/bin/sh\",\"session\":\"s\",\"ts\":3}
not json at all
{\"type\":\"sensor_exit\",\"instance\":\"a\",\"pid\":100,\"ppid\":1,\"exe\":\"/bin/sh\",\"session\":\"s\",\"ts\":4}
";
        assert_eq!(sensor_instances(record), vec![200]);
        assert_eq!(sensor_instances(""), Vec::<Pid>::new());
    }

    #[test]
    fn the_preload_fact_only_exists_for_a_session_that_carries_a_sensor() {
        let (mut handler, _events) = handler_for(QUARANTINE_POLICY, vec![]);

        // No sensor: the question cannot exist.
        let mut child = rm_process(400, "a");
        child.env.remove("LD_PRELOAD");
        assert!(
            handler.preload_stripped(&child).is_none(),
            "a session without a sensor never raises the fact"
        );

        // A sensor, and a child that keeps the preload: quiet.
        handler.session.sensor = Some(af_core::SensorMeta {
            preload: "/research/spikes/inprocess/libafsensor.so".to_string(),
            instances: vec![400],
            trace: None,
            registration: None,
        });
        child.env.insert(
            "LD_PRELOAD".to_string(),
            "/research/spikes/inprocess/libafsensor.so".to_string(),
        );
        assert!(
            handler.preload_stripped(&child).is_none(),
            "a child that carries the preload stays quiet"
        );

        // A sensor, and a child with no copy of it: the fact with evidence.
        child.env.remove("LD_PRELOAD");
        let detail = handler
            .preload_stripped(&child)
            .expect("the removal is sensed");
        assert!(
            detail.contains("none of the 1 sensor library"),
            "the evidence names what was removed: {detail}"
        );
    }

    #[test]
    fn a_static_binary_that_ignores_the_preload_still_carries_it() {
        let (mut handler, _events) = handler_for(QUARANTINE_POLICY, vec![]);
        handler.session.sensor = Some(af_core::SensorMeta {
            preload: "/research/spikes/inprocess/libafsensor.so".to_string(),
            instances: vec![],
            trace: None,
            registration: None,
        });
        // A static binary keeps the variable in its environment even though
        // the loader never reads it: the removal is the fact, not the
        // ignorance.
        let mut child = rm_process(400, "a");
        child.env.insert(
            "LD_PRELOAD".to_string(),
            "/research/spikes/inprocess/libafsensor.so".to_string(),
        );
        assert!(handler.preload_stripped(&child).is_none());
    }

    #[test]
    fn an_evidence_path_takes_the_form_the_open_stop_reports() {
        let cwd = Path::new("/work/session");
        // The monitor's own form: absolute, no `.` and `..`, no doubled
        // separators. The fact and the observed path must compare equal.
        assert_eq!(
            evidence_path(Path::new("trace.jsonl"), cwd),
            "/work/session/trace.jsonl"
        );
        assert_eq!(
            evidence_path(Path::new("../session/./trace.jsonl"), cwd),
            "/work/session/trace.jsonl"
        );
        assert_eq!(
            evidence_path(Path::new("/tmp/afw//trace.jsonl"), cwd),
            "/tmp/afw/trace.jsonl"
        );
        // `..` above the root cannot climb out of it.
        assert_eq!(
            evidence_path(Path::new("../../trace.jsonl"), cwd),
            "/trace.jsonl"
        );
    }

    #[test]
    fn the_session_names_its_own_evidence_files() {
        let mut session = SessionMeta::new(vec!["bash".to_string()], "/work".to_string());
        assert_eq!(session.evidence_kind("/work/t.jsonl"), None);
        session.trace = Some("/work/t.jsonl".to_string());
        assert_eq!(
            session.evidence_kind("/work/t.jsonl"),
            Some(af_core::EvidenceKind::Trace)
        );
        // A path that is close but not the file answers nothing, and a
        // session without the fact answers nothing for any path.
        assert_eq!(session.evidence_kind("/work/t.jsonl.bak"), None);
        session.trace = None;
        assert_eq!(session.evidence_kind("/work/t.jsonl"), None);

        let mut sensor = af_core::SensorMeta {
            preload: "/research/spikes/inprocess/libafsensor.so".to_string(),
            instances: vec![],
            trace: Some("/work/s.jsonl".to_string()),
            registration: Some("/work/s.reg".to_string()),
        };
        session.sensor = Some(sensor.clone());
        assert_eq!(
            session.evidence_kind("/work/s.jsonl"),
            Some(af_core::EvidenceKind::SensorTrace)
        );
        assert_eq!(
            session.evidence_kind("/work/s.reg"),
            Some(af_core::EvidenceKind::SensorRegistration)
        );
        sensor.registration = None;
        session.sensor = Some(sensor);
        assert_eq!(session.evidence_kind("/work/s.reg"), None);
    }
}
