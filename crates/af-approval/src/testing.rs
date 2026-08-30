//! Helpers for the tests of this crate.
//!
//! An [`af_core::ApprovalRequest`] holds references. A test therefore needs
//! an owner of the facts. [`Fixture`] is that owner. [`FakeConsole`] takes
//! the place of the real terminal, so a test never opens `/dev/tty`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use af_core::{
    Action, AgentMeta, ApprovalRequest, Decision, ProcessInfo, RiskLevel, RuleMatch, SessionId,
    SessionMeta, Verdict,
};

use crate::console::{Answer, Console};

/// Owner of the facts of one question.
pub(crate) struct Fixture {
    /// Metadata of the session.
    pub session: SessionMeta,
    /// The action that waits for a decision.
    pub action: Action,
    /// The process that performs the action.
    pub process: ProcessInfo,
    /// Ancestry of the process, nearest parent first.
    pub ancestry: Vec<ProcessInfo>,
    /// The verdict that caused the question.
    pub verdict: Verdict,
}

impl Fixture {
    /// Makes a question about a `psql` command with this SQL statement.
    pub fn psql(sql: &str) -> Self {
        Self::exec("psql", &["-c", sql])
    }

    /// Makes a question about a program with these arguments.
    pub fn exec(program: &str, args: &[&str]) -> Self {
        let mut argv = vec![program.to_string()];
        argv.extend(args.iter().map(|arg| arg.to_string()));
        let action = Action::Exec {
            exe: Some(format!("/usr/bin/{program}")),
            program: program.to_string(),
            argv: argv.clone(),
            cwd: Some("/home/dev/project".to_string()),
            env: Default::default(),
        };
        let process = ProcessInfo {
            pid: 40,
            ppid: Some(30),
            start_ticks: 400,
            exe: Some(format!("/usr/bin/{program}")),
            comm: program.to_string(),
            argv,
            cwd: Some("/home/dev/project".to_string()),
            ..Default::default()
        };
        Self::with(action, process)
    }

    /// Makes a question about a file that a process opens.
    pub fn file_open(path: &str, write: bool) -> Self {
        let action = Action::FileOpen {
            path: path.to_string(),
            write,
        };
        Self::with(action, proc_info("cat", 40, 30))
    }

    /// Makes a question about a network connection.
    pub fn network(host: &str, addr: &str, port: u16) -> Self {
        let action = Action::NetworkConnect {
            host: Some(host.to_string()),
            addr: addr.to_string(),
            port,
        };
        Self::with(action, proc_info("curl", 40, 30))
    }

    /// Makes a question from an action and the process that performs it.
    fn with(action: Action, process: ProcessInfo) -> Self {
        let mut session =
            SessionMeta::new(vec!["claude".to_string()], "/home/dev/project".to_string());
        session.session_id = SessionId::from("afw-test-session");
        session.root_pid = 10;
        session.agent = AgentMeta::from_program("claude");
        Self {
            session,
            action,
            process,
            ancestry: vec![
                proc_info("migrate.sh", 30, 20),
                proc_info("bash", 20, 10),
                proc_info("claude", 10, 1),
            ],
            verdict: Verdict::from_matches(vec![RuleMatch {
                rule_id: "database.destructive.drop-database".to_string(),
                title: "Drop a database".to_string(),
                category: "database".to_string(),
                risk: RiskLevel::ApprovalRequired,
                decision: Decision::ApprovalRequired,
                reason: "the statement removes a whole database".to_string(),
            }]),
        }
    }

    /// Returns the request that the approver reads.
    pub fn request(&self) -> ApprovalRequest<'_> {
        ApprovalRequest {
            session: &self.session,
            action: &self.action,
            process: &self.process,
            ancestry: &self.ancestry,
            verdict: &self.verdict,
        }
    }

    /// Changes the program of an exec action.
    pub fn set_program(&mut self, name: &str) {
        if let Action::Exec {
            exe, program, argv, ..
        } = &mut self.action
        {
            *exe = Some(format!("/usr/bin/{name}"));
            *program = name.to_string();
            if argv.is_empty() {
                argv.push(name.to_string());
            } else {
                argv[0] = name.to_string();
            }
        }
        self.process.exe = Some(format!("/usr/bin/{name}"));
        self.process.comm = name.to_string();
    }

    /// Changes the risk level of the verdict and of its first rule.
    pub fn set_risk(&mut self, risk: RiskLevel) {
        self.verdict.risk = risk;
        if let Some(matched) = self.verdict.matches.first_mut() {
            matched.risk = risk;
        }
    }
}

/// Makes one process record for a fixture.
fn proc_info(name: &str, pid: i32, ppid: i32) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid: Some(ppid),
        start_ticks: pid as u64 * 10,
        exe: Some(format!("/usr/bin/{name}")),
        comm: name.to_string(),
        argv: vec![name.to_string()],
        cwd: Some("/home/dev/project".to_string()),
        ..Default::default()
    }
}

/// What a [`FakeConsole`] wrote and read.
#[derive(Debug, Default)]
struct ConsoleLog {
    /// Everything that the approver wrote.
    text: String,
    /// How many times the approver read an answer.
    reads: usize,
}

/// A view of the work of a [`FakeConsole`].
///
/// The test keeps this view. The approver keeps the console itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConsoleWatch {
    /// The shared record of the console.
    log: Arc<Mutex<ConsoleLog>>,
}

impl ConsoleWatch {
    /// Returns everything that the approver wrote to the console.
    pub fn text(&self) -> String {
        self.log.lock().expect("console log").text.clone()
    }

    /// Returns how many answers the approver read.
    pub fn reads(&self) -> usize {
        self.log.lock().expect("console log").reads
    }
}

/// A terminal for tests. It gives answers from a list.
///
/// The console never blocks. A test with this console therefore always ends,
/// also when the approver waits without a limit.
pub(crate) struct FakeConsole {
    /// The answers that the console did not give yet.
    answers: VecDeque<Answer>,
    /// The record of the work of the console.
    watch: ConsoleWatch,
}

impl FakeConsole {
    /// Makes a console that gives these answers, first answer first.
    pub fn new(answers: Vec<Answer>) -> Self {
        Self {
            answers: answers.into(),
            watch: ConsoleWatch::default(),
        }
    }

    /// Returns a view of the work of this console.
    pub fn watch(&self) -> ConsoleWatch {
        self.watch.clone()
    }
}

impl Console for FakeConsole {
    fn write_text(&mut self, text: &str) {
        self.watch
            .log
            .lock()
            .expect("console log")
            .text
            .push_str(text);
    }

    fn read_line(&mut self, _timeout: Option<Duration>) -> Answer {
        self.watch.log.lock().expect("console log").reads += 1;
        self.answers.pop_front().unwrap_or(Answer::Ended)
    }
}
