//! The approver that asks the user on the terminal.

use std::time::{Duration, Instant};

use af_core::{display, ApprovalOutcome, ApprovalRequest, Approver};
use serde::{Deserialize, Serialize};

use crate::console::{Answer, Console, TtyConsole};
use crate::memory::SessionMemory;
use crate::mode::ApprovalMode;
use crate::prompt::render_prompt;

/// Time that the approver waits for an answer when nobody sets a limit.
///
/// A monitored process is frozen while the approver waits. The approver
/// therefore never waits without a limit by accident.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest number of answers that the approver reads for one question.
///
/// The approver denies after this number of answers that it does not
/// understand.
const MAX_ANSWERS: usize = 3;

/// Largest length of the operation text in a line on standard error.
const MAX_SUMMARY: usize = 120;

/// A count of the answers of one session.
///
/// `asked` counts every question. Every question raises exactly one of
/// `allowed`, `denied` and `terminated`. `from_memory` counts the questions
/// that an earlier session approval answered, so it is a part of `allowed`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverStats {
    /// How many questions the approver received.
    pub asked: usize,
    /// How many actions the approver let continue.
    pub allowed: usize,
    /// How many actions the approver stopped.
    pub denied: usize,
    /// How many times the approver ended the session.
    pub terminated: usize,
    /// How many questions the session memory answered.
    pub from_memory: usize,
}

/// The terminal that the approver uses.
enum Terminal {
    /// The approver did not open the terminal yet.
    Closed,
    /// The approver has a terminal.
    Open(Box<dyn Console>),
    /// The machine has no terminal for the approver.
    Missing,
}

/// Asks the user on the terminal.
///
/// The approver opens `/dev/tty`. It never reads the standard input, because
/// the monitored agent owns that stream. A read of the standard input takes
/// the keystrokes of the user away from the agent.
///
/// The approver always returns an answer. Every failure becomes
/// [`ApprovalOutcome::Deny`], because deny is the safe answer.
pub struct TerminalApprover {
    /// How the approver answers a question.
    mode: ApprovalMode,
    /// How long the approver waits for one answer.
    timeout: Option<Duration>,
    /// True when the approver writes colours.
    color: bool,
    /// The answers that hold for the whole session.
    memory: SessionMemory,
    /// A count of the answers of this session.
    stats: ApproverStats,
    /// The terminal of the user.
    terminal: Terminal,
}

impl TerminalApprover {
    /// Makes an approver with a mode.
    ///
    /// The approver waits two minutes for an answer. It writes colours, but
    /// it obeys the `NO_COLOR` environment variable.
    pub fn new(mode: ApprovalMode) -> Self {
        Self {
            mode,
            timeout: Some(DEFAULT_TIMEOUT),
            color: std::env::var_os("NO_COLOR").is_none(),
            memory: SessionMemory::new(),
            stats: ApproverStats::default(),
            terminal: Terminal::Closed,
        }
    }

    /// Sets how long the approver waits for an answer. `None` means it waits
    /// forever.
    ///
    /// Use `None` with care. A monitored process stays frozen until the user
    /// answers.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Switches the colours off.
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Returns how many questions the approver asked and how it answered them.
    pub fn stats(&self) -> ApproverStats {
        self.stats
    }

    /// Returns the answers that hold for the whole session.
    pub fn memory(&self) -> &SessionMemory {
        &self.memory
    }

    /// Uses a test terminal instead of `/dev/tty`.
    #[cfg(test)]
    pub(crate) fn with_console(mut self, console: impl Console + 'static) -> Self {
        self.terminal = Terminal::Open(Box::new(console));
        self
    }

    /// Acts as if the machine has no terminal.
    ///
    /// The test for a continuous-integration job uses this method. The test
    /// must not close the real terminal of the developer.
    #[cfg(test)]
    pub(crate) fn without_console(mut self) -> Self {
        self.terminal = Terminal::Missing;
        self
    }

    /// Returns the terminal and opens it at the first question.
    fn console(&mut self) -> Option<&mut dyn Console> {
        if matches!(self.terminal, Terminal::Closed) {
            self.terminal = match TtyConsole::open() {
                Ok(tty) => Terminal::Open(Box::new(tty)),
                Err(error) => {
                    warn(&format!(
                        "cannot open /dev/tty ({error}); the firewall cannot ask"
                    ));
                    Terminal::Missing
                }
            };
        }
        match &mut self.terminal {
            Terminal::Open(console) => Some(console.as_mut()),
            _ => None,
        }
    }

    /// Writes one line for the user.
    ///
    /// The line goes to the terminal when the approver asks questions. It
    /// goes to standard error in every other case, so a run without a
    /// terminal still leaves a record.
    fn notice(&mut self, text: &str) {
        if self.mode == ApprovalMode::Ask {
            if let Some(console) = self.console() {
                console.write_text(&format!("agent-firewall: {text}\n"));
                return;
            }
        }
        warn(text);
    }

    /// Counts one answer.
    fn count(&mut self, outcome: ApprovalOutcome) -> ApprovalOutcome {
        match outcome {
            ApprovalOutcome::Allow | ApprovalOutcome::AllowForSession => self.stats.allowed += 1,
            ApprovalOutcome::Deny => self.stats.denied += 1,
            ApprovalOutcome::TerminateSession => self.stats.terminated += 1,
        }
        outcome
    }

    /// Asks the question on the terminal and reads the answer.
    fn ask(&mut self, req: &ApprovalRequest<'_>) -> ApprovalOutcome {
        let prompt = render_prompt(req, self.color);
        let timeout = self.timeout;
        let deadline = timeout.map(|limit| Instant::now() + limit);

        let console = match self.console() {
            Some(console) => console,
            None => {
                warn(&format!(
                    "no terminal available; the firewall denies — {}",
                    describe(req)
                ));
                return ApprovalOutcome::Deny;
            }
        };
        console.write_text(&format!("\n{prompt}answer [a/s/d/t]: "));

        for attempt in 1..=MAX_ANSWERS {
            let left = deadline.map(|end| end.saturating_duration_since(Instant::now()));
            match console.read_line(left) {
                Answer::Line(text) => match parse_answer(&text) {
                    Some(outcome) => {
                        console.write_text(&format!("agent-firewall: {}\n", outcome.label()));
                        return outcome;
                    }
                    None if attempt < MAX_ANSWERS => {
                        console.write_text(
                            "agent-firewall: answer a, s, d or t.\nanswer [a/s/d/t]: ",
                        );
                    }
                    None => {
                        console.write_text(
                            "agent-firewall: no answer that the firewall understands; deny.\n",
                        );
                        return ApprovalOutcome::Deny;
                    }
                },
                Answer::TimedOut => {
                    let seconds = timeout.map(|t| t.as_secs()).unwrap_or(0);
                    console.write_text(&format!(
                        "\nagent-firewall: no answer after {seconds} seconds; deny.\n"
                    ));
                    return ApprovalOutcome::Deny;
                }
                Answer::Ended => {
                    warn(&format!(
                        "the terminal closed before an answer; the firewall denies — {}",
                        describe(req)
                    ));
                    return ApprovalOutcome::Deny;
                }
            }
        }
        ApprovalOutcome::Deny
    }
}

impl Approver for TerminalApprover {
    fn request(&mut self, req: &ApprovalRequest<'_>) -> ApprovalOutcome {
        self.stats.asked += 1;

        if self.memory.is_allowed(req) {
            self.stats.from_memory += 1;
            let text = format!("allowed by an earlier session answer — {}", describe(req));
            self.notice(&text);
            return self.count(ApprovalOutcome::Allow);
        }

        let outcome = match self.mode {
            ApprovalMode::AutoAllow => {
                warn(&format!("auto-allow — {}", describe(req)));
                ApprovalOutcome::Allow
            }
            ApprovalMode::AutoDeny => {
                warn(&format!("auto-deny — {}", describe(req)));
                ApprovalOutcome::Deny
            }
            ApprovalMode::Ask => self.ask(req),
        };

        if outcome == ApprovalOutcome::AllowForSession {
            self.memory.allow(req);
        }
        self.count(outcome)
    }
}

/// Reads the answer of the user.
///
/// An empty line gives `Deny`, because deny is the safe answer. A word that
/// the firewall does not know gives `None`.
fn parse_answer(text: &str) -> Option<ApprovalOutcome> {
    match text.trim().to_ascii_lowercase().as_str() {
        "" => Some(ApprovalOutcome::Deny),
        "a" | "allow" | "y" | "yes" => Some(ApprovalOutcome::Allow),
        "s" | "session" => Some(ApprovalOutcome::AllowForSession),
        "d" | "deny" | "n" | "no" => Some(ApprovalOutcome::Deny),
        "t" | "terminate" | "q" => Some(ApprovalOutcome::TerminateSession),
        _ => None,
    }
}

/// Describes a question in one short line for a log.
///
/// The line names the rule, because a run without a terminal must still show
/// why the firewall answered.
fn describe(req: &ApprovalRequest<'_>) -> String {
    let rule = req
        .verdict
        .top_match()
        .map(|matched| matched.rule_id.as_str())
        .unwrap_or("(no rule matched)");
    let summary = display::sanitize(&display::truncate(&req.action.summary(), MAX_SUMMARY));
    format!("rule {rule} — {summary}")
}

/// Writes one line to standard error.
fn warn(text: &str) {
    eprintln!("agent-firewall: {text}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeConsole, Fixture};

    /// Time that proves that a call returns at once.
    const FAST: Duration = Duration::from_secs(2);

    /// A limit that makes a wait visible in a test.
    fn long_timeout() -> Option<Duration> {
        Some(Duration::from_secs(3600))
    }

    #[test]
    fn auto_deny_denies_without_a_terminal() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(Vec::new());
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::AutoDeny)
            .with_timeout(long_timeout())
            .with_color(false)
            .with_console(console);

        let start = Instant::now();
        let outcome = approver.request(&fixture.request());

        assert_eq!(outcome, ApprovalOutcome::Deny);
        assert!(start.elapsed() < FAST, "the approver waited");
        assert_eq!(watch.reads(), 0, "the approver read the terminal");
        assert_eq!(watch.text(), "", "the approver wrote to the terminal");
        assert_eq!(
            approver.stats(),
            ApproverStats {
                asked: 1,
                denied: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn auto_allow_allows_without_a_terminal() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(Vec::new());
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::AutoAllow)
            .with_timeout(long_timeout())
            .with_color(false)
            .with_console(console);

        let start = Instant::now();
        let outcome = approver.request(&fixture.request());

        assert_eq!(outcome, ApprovalOutcome::Allow);
        assert!(start.elapsed() < FAST, "the approver waited");
        assert_eq!(watch.reads(), 0);
        assert_eq!(watch.text(), "");
        assert_eq!(
            approver.stats(),
            ApproverStats {
                asked: 1,
                allowed: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn ask_without_a_terminal_denies_and_does_not_wait() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_timeout(long_timeout())
            .with_color(false)
            .without_console();

        let start = Instant::now();
        let outcome = approver.request(&fixture.request());

        assert_eq!(outcome, ApprovalOutcome::Deny);
        assert!(start.elapsed() < FAST, "the approver waited");
        assert_eq!(approver.stats().denied, 1);
    }

    #[test]
    fn the_question_reaches_the_terminal() {
        let fixture = Fixture::psql("DROP DATABASE customer_prod");
        let console = FakeConsole::new(vec![Answer::Line("a".into())]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(
            approver.request(&fixture.request()),
            ApprovalOutcome::Allow
        );
        let text = watch.text();
        assert!(text.contains("Agent Firewall"), "{text}");
        assert!(text.contains("DROP DATABASE customer_prod"), "{text}");
        assert!(text.contains("answer [a/s/d/t]:"), "{text}");
        assert!(text.contains("agent-firewall: allow"), "{text}");
    }

    #[test]
    fn every_known_word_gives_the_right_answer() {
        let cases = [
            ("a", ApprovalOutcome::Allow),
            ("allow", ApprovalOutcome::Allow),
            ("y", ApprovalOutcome::Allow),
            ("YES", ApprovalOutcome::Allow),
            ("s", ApprovalOutcome::AllowForSession),
            ("session", ApprovalOutcome::AllowForSession),
            ("d", ApprovalOutcome::Deny),
            ("deny", ApprovalOutcome::Deny),
            ("n", ApprovalOutcome::Deny),
            ("no", ApprovalOutcome::Deny),
            ("t", ApprovalOutcome::TerminateSession),
            ("terminate", ApprovalOutcome::TerminateSession),
            ("q", ApprovalOutcome::TerminateSession),
            ("  a  ", ApprovalOutcome::Allow),
        ];
        for (text, want) in cases {
            let fixture = Fixture::psql("DROP DATABASE prod");
            let console = FakeConsole::new(vec![Answer::Line(text.into())]);
            let mut approver = TerminalApprover::new(ApprovalMode::Ask)
                .with_color(false)
                .with_console(console);
            assert_eq!(
                approver.request(&fixture.request()),
                want,
                "answer: {text:?}"
            );
        }
    }

    #[test]
    fn an_empty_line_denies() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![Answer::Line(String::new())]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert_eq!(watch.reads(), 1, "the approver asked again");
    }

    #[test]
    fn the_approver_asks_again_after_a_word_that_it_does_not_know() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![
            Answer::Line("maybe".into()),
            Answer::Line("a".into()),
        ]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Allow);
        assert_eq!(watch.reads(), 2);
        assert!(watch.text().contains("answer a, s, d or t"), "{}", watch.text());
    }

    #[test]
    fn three_words_that_the_approver_does_not_know_deny() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![
            Answer::Line("what".into()),
            Answer::Line("why".into()),
            Answer::Line("how".into()),
            Answer::Line("a".into()),
        ]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert_eq!(watch.reads(), 3, "the approver read too many answers");
    }

    #[test]
    fn a_timeout_denies() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![Answer::TimedOut]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_timeout(Some(Duration::from_secs(30)))
            .with_color(false)
            .with_console(console);

        let start = Instant::now();
        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert!(start.elapsed() < FAST, "the approver waited");
        assert!(watch.text().contains("no answer after 30 seconds"), "{}", watch.text());
    }

    #[test]
    fn a_closed_terminal_denies() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![Answer::Ended]);
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert_eq!(approver.stats().denied, 1);
    }

    #[test]
    fn a_session_answer_answers_the_same_question_again() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![Answer::Line("s".into())]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        assert_eq!(
            approver.request(&fixture.request()),
            ApprovalOutcome::AllowForSession
        );
        assert_eq!(approver.memory().len(), 1);

        let again = Fixture::psql("DROP DATABASE prod");
        assert_eq!(approver.request(&again.request()), ApprovalOutcome::Allow);
        assert_eq!(watch.reads(), 1, "the approver asked the same question again");
        assert!(
            watch.text().contains("allowed by an earlier session answer"),
            "{}",
            watch.text()
        );
        assert_eq!(
            approver.stats(),
            ApproverStats {
                asked: 2,
                allowed: 2,
                denied: 0,
                terminated: 0,
                from_memory: 1,
            }
        );
    }

    #[test]
    fn a_session_answer_does_not_open_a_different_action() {
        let fixture = Fixture::psql("DROP DATABASE a");
        let console = FakeConsole::new(vec![
            Answer::Line("s".into()),
            Answer::Line("d".into()),
        ]);
        let watch = console.watch();
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        approver.request(&fixture.request());
        let other = Fixture::psql("DROP DATABASE b");
        assert_eq!(approver.request(&other.request()), ApprovalOutcome::Deny);
        assert_eq!(watch.reads(), 2, "the approver did not ask the second question");
    }

    #[test]
    fn a_session_answer_also_works_in_auto_deny_mode() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let mut approver = TerminalApprover::new(ApprovalMode::AutoDeny)
            .with_color(false)
            .without_console();
        approver.memory.allow(&fixture.request());

        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Allow);
        assert_eq!(approver.stats().from_memory, 1);
    }

    #[test]
    fn the_approver_counts_every_answer() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(vec![
            Answer::Line("a".into()),
            Answer::Line("d".into()),
            Answer::Line("t".into()),
        ]);
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_color(false)
            .with_console(console);

        for _ in 0..3 {
            approver.request(&fixture.request());
        }
        assert_eq!(
            approver.stats(),
            ApproverStats {
                asked: 3,
                allowed: 1,
                denied: 1,
                terminated: 1,
                from_memory: 0,
            }
        );
    }

    #[test]
    fn an_empty_terminal_denies_instead_of_waiting() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let console = FakeConsole::new(Vec::new());
        let mut approver = TerminalApprover::new(ApprovalMode::Ask)
            .with_timeout(long_timeout())
            .with_color(false)
            .with_console(console);

        let start = Instant::now();
        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert!(start.elapsed() < FAST);
    }

    #[test]
    fn the_approver_is_an_approver_object() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let mut approver: Box<dyn Approver> = Box::new(
            TerminalApprover::new(ApprovalMode::AutoDeny)
                .with_color(false)
                .without_console(),
        );
        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
    }
}
