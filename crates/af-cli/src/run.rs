//! The `run` sub-command.
//!
//! This module connects every layer of the firewall. It launches the program
//! through the monitor, builds the provenance graph from the event stream,
//! asks the policy engine about each new program, and holds the process while
//! the user answers.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};

use af_approval::{ApprovalMode, TerminalApprover};
use af_core::{
    display, Action, ApprovalOutcome, ApprovalRequest, EvalContext, Event, EventKind, EventSink,
    MemoryEffect, MonitorCapability, Pid, PolicyEngine, ProcessInfo, SessionMemory, SessionMeta,
    TimestampNanos, Verdict,
};
use af_monitor::{
    InputSnapshot, Intercept, Monitor, MonitorConfig, MonitorHandler, SyscallFilter,
};
use af_provenance::ProcessGraph;
use af_recorder::{FanoutSink, Retention, StreamSink, TraceWriter};
use anyhow::{bail, Context, Result};

use crate::cli::RunArgs;
use crate::normalize;
use crate::policy_cmds::load_policy;

/// The exit code that the firewall returns when it stopped the session.
pub const EXIT_BLOCKED: i32 = 3;

/// Runs the `run` sub-command and returns the exit code of the process.
pub fn run(args: RunArgs) -> Result<i32> {
    if args.command.is_empty() {
        bail!("no command given after `--`");
    }

    let cwd = match &args.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let mut session = SessionMeta::new(args.command.clone(), cwd.display().to_string());
    session
        .baseline
        .insert("git_remotes".to_string(), git_remotes(&cwd));

    let policy = load_policy(&args.policy).context("cannot load the rules")?;
    let syscall_filter = parse_syscall_filter(&args.syscall_filter)?;
    let mode = approval_mode(&args)?;
    let approver = TerminalApprover::new(mode)
        .with_timeout(args.approval_timeout.map(std::time::Duration::from_secs));
    let sink = build_sink(&args)?;

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
        blocked: false,
        last_event_ts: session.started_at,
        answered: HashMap::new(),
    };

    let capabilities = Monitor::capabilities(syscall_filter);
    warn_about_missing_capabilities(&capabilities);
    handler.emit(Event::new(
        session.session_id.clone(),
        0,
        EventKind::SessionStart {
            meta: Box::new(session.clone()),
            capabilities,
        },
    ));

    let config = MonitorConfig {
        command: args.command.clone(),
        cwd: args.cwd.clone(),
        env_allowlist: Vec::new(),
        capture_input: !args.no_input_capture,
        syscall_filter,
        ..MonitorConfig::default()
    };

    let outcome = Monitor::run(&config, &session, &mut handler).context("the monitor failed")?;

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
        None => bail!(
            "`--syscall-filter` accepts write-only, all-opens or off, but it got `{text}`"
        ),
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
fn build_sink(args: &RunArgs) -> Result<Box<dyn EventSink>> {
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();
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
    interventions: usize,
    blocked: bool,
    /// What the session remembers. The handler owns it and applies every
    /// effect that the engine asks for, in event order.
    memory: SessionMemory,
    /// Time of the newest event that the monitor produced.
    ///
    /// The memory keys on event time and never on a clock, so the replay of
    /// the trace of this session gives the same answers.
    last_event_ts: TimestampNanos,
    /// The answer that this session already gave for one held system call.
    ///
    /// A refused call comes back. A program that gets `EPERM` from an open
    /// usually tries the same open again, or tries the next file of a list,
    /// and a firewall that asks the same question at every try is the thing
    /// that makes a user switch the firewall off. The key is the rule and the
    /// action, so a different file is still a new question.
    ///
    /// The approver has a memory of its own, but that one holds only what the
    /// user allowed **for the session**. A one-time answer and a refusal are
    /// not in it, and both have to hold here.
    answered: HashMap<String, Intercept>,
}

impl FirewallHandler {
    /// Sends one event to the graph and to storage.
    fn emit(&mut self, event: Event) {
        self.last_event_ts = event.ts;
        self.graph.apply(&event);
        if let Err(error) = self.sink.record(&event) {
            eprintln!("agent-firewall: cannot record an event: {error}");
        }
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
    ) -> (Verdict, Vec<MemoryEffect>) {
        self.policy.evaluate_with_memory(
            &EvalContext::new(&self.session, action, process, ancestry).at(self.last_event_ts),
            &self.memory,
        )
    }

    /// Evaluates every action that one exec produces.
    ///
    /// The new program is one action. Its standard input and its script are
    /// two more actions, because a dangerous statement often stays out of the
    /// command line.
    fn evaluate(
        &self,
        process: &ProcessInfo,
        ancestry: &[ProcessInfo],
        input: Option<&InputSnapshot>,
        scan_script: bool,
    ) -> (Action, Verdict, Vec<MemoryEffect>) {
        let exec_action = exec_action(process);
        let mut candidates: Vec<(Action, Verdict)> = Vec::new();
        let mut effects: Vec<MemoryEffect> = Vec::new();

        let (verdict, mut wanted) = self.evaluate_one(&exec_action, process, ancestry);
        effects.append(&mut wanted);
        candidates.push((exec_action.clone(), verdict));

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
                let (verdict, mut wanted) = self.evaluate_one(&action, process, ancestry);
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
}

impl MonitorHandler for FirewallHandler {
    fn on_event(&mut self, event: Event) {
        self.emit(event);
    }

    fn on_exec(
        &mut self,
        process: &ProcessInfo,
        ancestry_pids: &[Pid],
        input: Option<&InputSnapshot>,
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
        let ancestry = self.ancestry_of(process.pid, ancestry_pids);
        let (action, verdict, effects) = self.evaluate(&judged, &ancestry, input, scan_script);
        // The engine only reads the memory. The handler writes it, in event
        // order, so the replay of this trace reaches the same state.
        let ts = self.last_event_ts;
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

        self.interventions += 1;
        if self.explain_on_stderr || verdict.decision != af_core::Decision::ApprovalRequired {
            eprintln!(
                "\n{}\n",
                display::explain(&ancestry, &judged, &action, &verdict)
            );
        }
        match verdict.decision {
            af_core::Decision::Deny => {
                self.blocked = true;
                Intercept::Deny
            }
            af_core::Decision::Terminate => {
                self.blocked = true;
                Intercept::TerminateSession
            }
            _ => self.ask(&judged, &ancestry, &action, &verdict),
        }
    }

    fn on_syscall(&mut self, pid: Pid, action: &Action, ancestry_pids: &[Pid]) -> Intercept {
        // The process is already known from its exec event, so the handler
        // reads it from the graph instead of asking `/proc` again. A session
        // makes many of these stops and every one of them holds a process.
        let process = self
            .graph
            .process(pid)
            .unwrap_or_else(|| ProcessInfo::from_pid(pid));
        let ancestry = self.ancestry_of(pid, ancestry_pids);

        let (verdict, effects) = self.evaluate_one(action, &process, &ancestry);
        let ts = self.last_event_ts;
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
        // with it. The session answers it one time.
        let key = answer_key(action, &verdict);
        if let Some(answer) = self.answered.get(&key) {
            return *answer;
        }

        self.interventions += 1;
        if self.explain_on_stderr || verdict.decision != af_core::Decision::ApprovalRequired {
            eprintln!(
                "\n{}\n",
                display::explain(&ancestry, &process, action, &verdict)
            );
        }
        let answer = match verdict.decision {
            // A file open and a connection have not happened yet, so letting
            // the call fail stops the action completely. The program then
            // gets an ordinary permission error and can say so in its own
            // words, which `SIGKILL` would take away from it.
            af_core::Decision::Deny => {
                self.blocked = true;
                Intercept::Refuse
            }
            af_core::Decision::Terminate => {
                self.blocked = true;
                Intercept::TerminateSession
            }
            _ => match self.ask(&process, &ancestry, action, &verdict) {
                Intercept::Deny => Intercept::Refuse,
                other => other,
            },
        };
        self.answered.insert(key, answer);
        answer
    }
}

/// Makes the key under which the session remembers one answer.
///
/// The key names the rule and the action, and never the process, so the same
/// open of the same file gets one question however often a program tries it.
fn answer_key(action: &Action, verdict: &Verdict) -> String {
    let rule = verdict
        .top_match()
        .map(|matched| matched.rule_id.as_str())
        .unwrap_or("no-rule");
    format!("{rule}|{}|{}", action.kind(), action.summary())
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
