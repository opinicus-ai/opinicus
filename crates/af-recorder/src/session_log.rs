//! The durable plain-text log of one session.
//!
//! A trace is the machine's memory of a session, and it is opt-in: a user
//! who passes no `--trace` still needs a record that survives the terminal
//! — for a bug report, for an incident, for "what did the firewall stop
//! yesterday?". The session log is that record: one plain-text file per
//! session, written by the launcher of every `run`, holding the
//! support-relevant lines only. A session that nothing stopped makes no
//! noise in its log beyond the start and the end, in step with the
//! interruption budget ([docs/PRODUCT.md](https://github.com/opinicus-ai/opinicus/blob/main/docs/PRODUCT.md) §5).
//!
//! # Where the log lives
//!
//! `${XDG_STATE_HOME:-$HOME/.local/state}/agent-firewall/sessions/<session
//! id>.log`, one file per session. The XDG base directory specification
//! assigns state that persists between runs and is not portable — logs and
//! history — to `$XDG_STATE_HOME`, and this repository already keeps the
//! other XDG classes apart: consent in `$XDG_CONFIG_HOME`
//! (`af-telemetry` `Consent::default_path`) and the telemetry outbox in
//! `$XDG_DATA_HOME` (`af-telemetry` `default_outbox_path`). The session log
//! completes the set: one directory per XDG class, so a user who wants the
//! logs gone removes one directory and touches nothing else.
//!
//! The file is created with the permission mode `0600`, exactly like a
//! trace file ([`crate::TraceWriter::create`]), because a log line holds
//! command lines and paths that no other local user may read. The writer
//! appends and never truncates, and it flushes every line: a session log
//! must survive a hard stop of the session, also a `SIGKILL` of the
//! monitor itself.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use af_core::{
    display, ApprovalOutcome, Decision, Event, EventKind, EventSink, Result, TimestampNanos,
    Verdict,
};

/// Largest number of characters of a free text in one log line.
///
/// A log line must stay readable on a terminal. Command lines and evidence
/// lines are cut with a visible ellipsis, never silently.
const MAX_TEXT: usize = 160;

/// Largest number of characters of the session command in the start line.
const MAX_COMMAND: usize = 200;

/// Writes the durable plain-text log of one session.
///
/// The sink turns every event into at most one line ([`SessionLog::line_for`])
/// and writes it through, so the file on disk is complete up to the last
/// event the session produced, whatever way the session ends.
pub struct SessionLog {
    /// Where the lines go.
    out: Box<dyn Write + Send>,
    /// Path of the log file, for the user to read.
    path: PathBuf,
    /// How many lines the log wrote.
    lines: u64,
}

impl SessionLog {
    /// Opens the log of one session.
    ///
    /// The function makes the directory of the file when it is missing, so a
    /// fresh installation needs no preparation. The file is created with the
    /// permission mode `0600` whatever the umask of the session is, and an
    /// existing file is appended to, never truncated.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self::to_writer(BufWriter::new(file), path))
    }

    /// Makes a log that puts its lines into any destination.
    ///
    /// `path` is the name the log reports about itself; a test can point it
    /// at a destination that has no file.
    pub fn to_writer<W: Write + Send + 'static>(writer: W, path: &Path) -> Self {
        Self {
            out: Box::new(writer),
            path: path.to_path_buf(),
            lines: 0,
        }
    }

    /// Returns the path of the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns how many lines the log wrote.
    pub fn lines(&self) -> u64 {
        self.lines
    }

    /// Returns the default directory of the session logs:
    /// `${XDG_STATE_HOME:-$HOME/.local/state}/agent-firewall/sessions`.
    pub fn default_dir() -> PathBuf {
        let base = std::env::var_os("XDG_STATE_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .map(|home| PathBuf::from(home).join(".local").join("state"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("agent-firewall").join("sessions")
    }

    /// Returns the default path of the log of one session.
    pub fn default_path(session_id: &str) -> PathBuf {
        Self::default_dir().join(format!("{session_id}.log"))
    }

    /// Returns the support line of one event, or `None` when the event says
    /// nothing that support needs.
    ///
    /// The line is plain text: a time stamp, a kind, and the facts that name
    /// the decision — the rule identifier above all. Free text is sanitized
    /// (a hostile program can write escape codes into its command line) and
    /// cut to [`MAX_TEXT`] characters.
    pub fn line_for(event: &Event) -> Option<String> {
        let at = iso8601(event.ts);
        let pid = event.pid;
        match &event.kind {
            EventKind::SessionStart { meta, .. } => {
                let command = clean(&meta.command.join(" "), MAX_COMMAND);
                let agent = match &meta.detection {
                    Some(agent) => format!(
                        " agent={} ({:.2})",
                        clean(&agent.name, MAX_TEXT),
                        agent.confidence
                    ),
                    None => String::new(),
                };
                Some(format!(
                    "{at} session {} started: {command} (cwd {}){}",
                    meta.session_id,
                    clean(&meta.cwd, MAX_TEXT),
                    agent
                ))
            }
            EventKind::SessionEnd {
                exit_code,
                process_count,
            } => Some(format!(
                "{at} session {} ended: exit={} processes={}",
                event.session_id,
                match exit_code {
                    Some(code) => code.to_string(),
                    None => "none".to_string(),
                },
                process_count
            )),
            EventKind::PolicyDecision {
                action, verdict, ..
            } => {
                if verdict.decision == Decision::Allow {
                    return None;
                }
                Some(format!(
                    "{at} decision {} {}: {} (pid {pid})",
                    verdict.decision.label(),
                    rules_of(verdict),
                    clean(&action.summary(), MAX_TEXT),
                ))
            }
            EventKind::ApprovalRequested { action, rule_id } => Some(format!(
                "{at} question rule={rule_id}: {} (pid {pid})",
                clean(&action.summary(), MAX_TEXT),
            )),
            EventKind::ApprovalResolved {
                rule_id,
                outcome,
                waited_ms,
            } => Some(format!(
                "{at} answer rule={rule_id}: {} after {waited_ms}ms",
                outcome_label(*outcome),
            )),
            EventKind::QuarantineStarted { rule, evidence } => Some(format!(
                "{at} quarantine rule={rule}: {} (pid {pid})",
                clean(evidence, MAX_TEXT),
            )),
            EventKind::QuarantineResolved { rule, outcome } => Some(format!(
                "{at} quarantine resolved rule={rule}: {}",
                outcome_label(*outcome),
            )),
            EventKind::Tamper { kind, detail } => Some(format!(
                "{at} tamper {kind}: {} (pid {pid})",
                clean(detail, MAX_TEXT),
            )),
            EventKind::ProcessUnlinked { detach, .. } => Some(format!(
                "{at} unlinked pid={pid} sid={} root_sid={}",
                detach.sid, detach.root_sid
            )),
            EventKind::KernelDenied { rule, path } => Some(format!(
                "{at} kernel denied {}: rule={}",
                clean(path, MAX_TEXT),
                rule.as_deref().unwrap_or("(no rule class)")
            )),
            EventKind::MonitorWarning { message } => {
                Some(format!("{at} warning: {}", clean(message, MAX_TEXT)))
            }
            _ => None,
        }
    }
}

impl EventSink for SessionLog {
    fn record(&mut self, event: &Event) -> Result<()> {
        if let Some(line) = Self::line_for(event) {
            // Every line goes through to the kernel: the log is small, and
            // its whole point is to survive the way the session ended.
            self.out.write_all(line.as_bytes())?;
            self.out.write_all(b"\n")?;
            self.out.flush()?;
            self.lines += 1;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(self.out.flush()?)
    }
}

impl std::fmt::Debug for SessionLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLog")
            .field("path", &self.path)
            .field("lines", &self.lines)
            .finish()
    }
}

/// Names the rules of a verdict, in the order of the verdict.
///
/// The rules of one verdict are what support needs first: a false positive
/// report names them, and the report path of the CLI reads them out of the
/// trace.
fn rules_of(verdict: &Verdict) -> String {
    let ids: Vec<&str> = verdict
        .matches
        .iter()
        .map(|matched| matched.rule_id.as_str())
        .collect();
    if ids.is_empty() {
        "(no rule matched)".to_string()
    } else {
        format!("rule={}", ids.join(","))
    }
}

/// Returns the label of an answer, in the words the user reads.
fn outcome_label(outcome: ApprovalOutcome) -> &'static str {
    match outcome {
        ApprovalOutcome::Allow => "allow",
        ApprovalOutcome::AllowForSession => "allow-for-session",
        ApprovalOutcome::Deny => "deny",
        ApprovalOutcome::TerminateSession => "terminate",
    }
}

/// Sanitizes and cuts a free text.
///
/// Control characters never reach the log — a hostile program can write
/// escape codes into its command line — and a long text is cut where the cut
/// is visible.
fn clean(text: &str, max_chars: usize) -> String {
    display::sanitize(&display::truncate(text, max_chars))
}

/// Formats a nanosecond time stamp as UTC ISO-8601, to the millisecond.
///
/// The conversion is the civil-date algorithm of Howard Hinnant
/// (chrono-free), so the log carries absolute times that a person can line
/// up with other logs of the same machine.
fn iso8601(ts: TimestampNanos) -> String {
    let nanos = ts as i64;
    let secs = nanos.div_euclid(1_000_000_000);
    let millis = nanos.rem_euclid(1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let of_day = secs.rem_euclid(86_400);
    let (hour, minute, second) = (of_day / 3_600, (of_day % 3_600) / 60, of_day % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Converts days after the Unix epoch to a civil (year, month, day) date.
fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u64, day as u64)
}
