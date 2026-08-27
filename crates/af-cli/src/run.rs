//! The `run` sub-command.
//!
//! This module connects every layer of the firewall. It launches the program
//! through the monitor, builds the provenance graph from the event stream,
//! asks the policy engine about each new program, and holds the process while
//! the user answers.

use std::io;
use std::path::PathBuf;

use af_approval::{ApprovalMode, TerminalApprover};
use af_core::{
    display, Action, ApprovalOutcome, ApprovalRequest, EvalContext, Event, EventKind, EventSink,
    MonitorCapability, Pid, PolicyEngine, ProcessInfo, SessionMeta, Verdict,
};
use af_monitor::{InputSnapshot, Intercept, Monitor, MonitorConfig, MonitorHandler};
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
    let session = SessionMeta::new(args.command.clone(), cwd.display().to_string());

    let policy = load_policy(&args.policy).context("cannot load the rules")?;
    let mode = approval_mode(&args)?;
    let approver = TerminalApprover::new(mode)
        .with_timeout(args.approval_timeout.map(std::time::Duration::from_secs));
    let sink = build_sink(&args)?;

    let mut handler = FirewallHandler {
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
    };

    let capabilities = Monitor::capabilities();
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
}

impl FirewallHandler {
    /// Sends one event to the graph and to storage.
    fn emit(&mut self, event: Event) {
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
    ) -> (Action, Verdict) {
        let exec_action = exec_action(process);
        let mut candidates: Vec<(Action, Verdict)> = Vec::new();

        let verdict = self.policy.evaluate(&EvalContext::new(
            &self.session,
            &exec_action,
            process,
            ancestry,
        ));
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
                let verdict = self.policy.evaluate(&EvalContext::new(
                    &self.session,
                    &action,
                    process,
                    ancestry,
                ));
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

        (display_action, combined)
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
        let (action, verdict) = self.evaluate(&judged, &ancestry, input, scan_script);

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
