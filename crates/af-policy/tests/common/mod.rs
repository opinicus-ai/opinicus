//! Small helpers that build a deterministic evaluation context.
//!
//! Every test in this crate uses the same session identifier and the same
//! start time, so a test run never depends on a clock.

#![allow(dead_code)]

use std::collections::BTreeMap;

use af_core::process::InputSource;
use af_core::{
    Action, AgentKind, AgentMeta, Decision, EvalContext, ProcessInfo, RiskLevel, SessionId,
    SessionMemory, SessionMeta, TimestampNanos, Verdict, EVENT_SCHEMA_VERSION,
};

/// How many nanoseconds are in one second.
pub const SECOND: TimestampNanos = 1_000_000_000;

/// Holds the parts of a context, because `EvalContext` only borrows them.
pub struct Case {
    pub session: SessionMeta,
    pub action: Action,
    pub process: ProcessInfo,
    pub ancestry: Vec<ProcessInfo>,
}

impl Case {
    /// Returns the context that the policy engine reads.
    pub fn ctx(&self) -> EvalContext<'_> {
        EvalContext::new(&self.session, &self.action, &self.process, &self.ancestry)
    }

    /// Returns the context at one event time.
    pub fn ctx_at(&self, ts: TimestampNanos) -> EvalContext<'_> {
        self.ctx().at(ts)
    }

    /// Sets the parents of the process, nearest parent first.
    pub fn with_ancestry(mut self, comms: &[&str]) -> Self {
        self.ancestry = comms
            .iter()
            .enumerate()
            .map(|(index, comm)| process(2 + index as i32, comm, &[comm]))
            .collect();
        self
    }

    /// Adds one environment variable to the process and to the action.
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.process.env.insert(name.to_string(), value.to_string());
        if let Action::Exec { env, .. } = &mut self.action {
            env.insert(name.to_string(), value.to_string());
        }
        self
    }

    /// Replaces the action with content that the monitor captured.
    pub fn with_input(mut self, data: &str) -> Self {
        self.action = Action::Input {
            source: InputSource::Stdin,
            data: data.to_string(),
        };
        self
    }
}

/// Makes a process record.
pub fn process(pid: i32, comm: &str, argv: &[&str]) -> ProcessInfo {
    ProcessInfo {
        pid,
        comm: comm.to_string(),
        exe: Some(format!("/usr/bin/{comm}")),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        ..Default::default()
    }
}

/// Makes a session record with no clock and no random number.
pub fn session(cwd: &str) -> SessionMeta {
    SessionMeta {
        session_id: SessionId::from("afw-test-session"),
        started_at: 0,
        root_pid: 1,
        command: vec!["bash".to_string()],
        cwd: cwd.to_string(),
        agent: AgentMeta {
            kind: AgentKind::ClaudeCode,
            version: None,
            agent_session_id: None,
            tool_call_id: None,
        },
        schema_version: EVENT_SCHEMA_VERSION,
        detection: None,
        monitor_pid: 0,
        sensor: None,
        baseline: Default::default(),
    }
}

/// Makes a case for a program that starts.
pub fn exec(argv: &[&str]) -> Case {
    exec_in("/home/dev/app", argv)
}

/// Makes a case for a program that starts in a working directory.
pub fn exec_in(cwd: &str, argv: &[&str]) -> Case {
    let program = argv.first().copied().unwrap_or("sh");
    let name = program.rsplit('/').next().unwrap_or(program);
    let process = ProcessInfo {
        pid: 4242,
        comm: name.to_string(),
        exe: Some(if program.starts_with('/') {
            program.to_string()
        } else {
            format!("/usr/bin/{name}")
        }),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd: Some(cwd.to_string()),
        ..Default::default()
    };
    let action = Action::Exec {
        exe: process.exe.clone(),
        program: name.to_string(),
        argv: process.argv.clone(),
        cwd: Some(cwd.to_string()),
        env: BTreeMap::new(),
    };
    Case {
        session: session(cwd),
        action,
        process,
        ancestry: Vec::new(),
    }
}

/// Makes a case for a file that a process opens.
pub fn file_open(path: &str, write: bool) -> Case {
    Case {
        session: session("/home/dev/app"),
        action: Action::FileOpen {
            path: path.to_string(),
            write,
        },
        process: process(4242, "cat", &["cat", path]),
        ancestry: Vec::new(),
    }
}

/// Makes a case for a connection to another machine.
pub fn connect(host: &str, addr: &str, port: u16) -> Case {
    Case {
        session: session("/home/dev/app"),
        action: Action::NetworkConnect {
            host: Some(host.to_string()),
            addr: addr.to_string(),
            port,
        },
        process: process(4242, "curl", &["curl", host]),
        ancestry: Vec::new(),
    }
}

/// Returns the rule identifiers of a verdict.
pub fn ids(verdict: &Verdict) -> Vec<String> {
    verdict.matches.iter().map(|m| m.rule_id.clone()).collect()
}

/// Returns true when no rule reported more than the level `info`.
pub fn is_quiet(verdict: &Verdict) -> bool {
    verdict.decision == Decision::Allow && verdict.risk <= RiskLevel::Info
}

/// Plays a list of actions through an engine and keeps the memory.
///
/// The helper does exactly what the launcher and the replay command do: it
/// evaluates one action, applies the effects that the engine asks for, and
/// then goes to the next action. The list of verdicts comes back in order.
pub fn play(policy: &dyn af_core::PolicyEngine, steps: &[(TimestampNanos, &Case)]) -> Vec<Verdict> {
    let mut memory = SessionMemory::new();
    let mut out = Vec::new();
    for (ts, case) in steps {
        let ctx = case.ctx_at(*ts);
        let (verdict, effects) = policy.evaluate_with_memory(&ctx, &memory);
        for effect in effects {
            memory.apply(effect, *ts);
        }
        out.push(verdict);
    }
    out
}
