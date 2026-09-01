//! Tests of the durable plain-text session log.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use af_core::{
    Action, ApprovalOutcome, Decision, Event, EventKind, EventSink, ProcessInfo, RiskLevel,
    RuleMatch, SessionId, SessionMeta, Verdict,
};
use af_recorder::{Retention, SessionLog, TraceWriter};

/// Makes a directory for the log files of one test.
///
/// The directory lies under the crate, like the trace directories of
/// `tests/trace.rs`: the shared temporary directory of the machine can be
/// full, and a test of the storage must not fail for that reason.
fn temp_dir() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-logs");
    std::fs::create_dir_all(&base).expect("base directory");
    tempfile::Builder::new()
        .prefix("log-")
        .tempdir_in(&base)
        .expect("temporary directory")
}

fn session_meta() -> SessionMeta {
    let mut session = SessionMeta::new(
        vec!["bash".to_string(), "./agent-sim.sh".to_string()],
        "/home/dev/project".to_string(),
    );
    session.session_id = SessionId::from("afw-test-session");
    session.started_at = 1_800_000_000_000_000_000;
    session
}

fn decision(action: Action, rule: &str, decision: Decision) -> Event {
    let mut event = Event::new(
        SessionId::from("afw-test-session"),
        401,
        EventKind::PolicyDecision {
            action: Box::new(action),
            verdict: Box::new(Verdict::from_matches(vec![RuleMatch {
                rule_id: rule.to_string(),
                title: "Drop a database".to_string(),
                category: "database".to_string(),
                risk: RiskLevel::ApprovalRequired,
                decision,
                quarantine: false,
                reason: "the statement removes a whole database".to_string(),
            }])),
            ancestry: Vec::new(),
        },
    );
    event.ts = 1_800_000_001_000_000_000;
    event
}

#[test]
fn the_log_holds_the_support_lines_of_one_session() {
    let dir = temp_dir();
    let path = dir.path().join("afw-test-session.log");
    let mut log = SessionLog::open(&path).expect("open the log");

    let session = session_meta();
    log.record(&Event::new(
        session.session_id.clone(),
        400,
        EventKind::SessionStart {
            meta: Box::new(session.clone()),
            capabilities: Vec::new(),
        },
    ))
    .expect("write");
    log.record(&decision(
        Action::Exec {
            exe: Some("/usr/bin/psql".to_string()),
            program: "psql".to_string(),
            argv: vec![
                "psql".to_string(),
                "-c".to_string(),
                "DROP DATABASE customer_prod".to_string(),
            ],
            cwd: Some("/home/dev/project".to_string()),
            env: Default::default(),
        },
        "database.destructive.drop-database",
        Decision::ApprovalRequired,
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        401,
        EventKind::ApprovalRequested {
            action: Box::new(Action::Exec {
                exe: Some("/usr/bin/psql".to_string()),
                program: "psql".to_string(),
                argv: vec![
                    "psql".to_string(),
                    "-c".to_string(),
                    "DROP DATABASE customer_prod".to_string(),
                ],
                cwd: Some("/home/dev/project".to_string()),
                env: Default::default(),
            }),
            rule_id: "database.destructive.drop-database".to_string(),
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        401,
        EventKind::ApprovalResolved {
            rule_id: "database.destructive.drop-database".to_string(),
            outcome: ApprovalOutcome::Deny,
            waited_ms: 2_331,
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        402,
        EventKind::QuarantineStarted {
            rule: "tamper.quarantine".to_string(),
            evidence: "a signal to the monitor".to_string(),
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        402,
        EventKind::QuarantineResolved {
            rule: "tamper.quarantine".to_string(),
            outcome: ApprovalOutcome::TerminateSession,
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        400,
        EventKind::SessionEnd {
            exit_code: Some(3),
            process_count: 5,
        },
    ))
    .expect("write");
    log.flush().expect("flush");
    drop(log);

    let text = std::fs::read_to_string(&path).expect("read the log back");
    assert!(
        text.contains("session afw-test-session started: bash ./agent-sim.sh"),
        "{text}"
    );
    assert!(text.contains("cwd /home/dev/project"), "{text}");
    assert!(
        text.contains("decision approval-required rule=database.destructive.drop-database"),
        "every decision names its rule:\n{text}"
    );
    assert!(text.contains("DROP DATABASE customer_prod"), "{text}");
    assert!(
        text.contains("question rule=database.destructive.drop-database"),
        "{text}"
    );
    assert!(
        text.contains("answer rule=database.destructive.drop-database: deny after 2331ms"),
        "{text}"
    );
    assert!(
        text.contains("quarantine rule=tamper.quarantine: a signal to the monitor"),
        "{text}"
    );
    assert!(
        text.contains("quarantine resolved rule=tamper.quarantine: terminate"),
        "{text}"
    );
    assert!(
        text.contains("session afw-test-session ended: exit=3 processes=5"),
        "{text}"
    );
    // Every line names its time, in a form a person can line up with the
    // other logs of the machine.
    for line in text.lines() {
        assert!(line.starts_with("20"), "a log line names its time: {line}");
    }
    assert_eq!(
        text.lines().count(),
        7,
        "the log writes one line per support-relevant event:\n{text}"
    );
}

#[test]
fn a_quiet_session_logs_only_its_frame() {
    let dir = temp_dir();
    let path = dir.path().join("quiet.log");
    let mut log = SessionLog::open(&path).expect("open the log");
    let session = session_meta();
    log.record(&Event::new(
        session.session_id.clone(),
        400,
        EventKind::SessionStart {
            meta: Box::new(session.clone()),
            capabilities: Vec::new(),
        },
    ))
    .expect("write");

    // The ordinary traffic of a session says nothing that support needs.
    log.record(&Event::new(
        session.session_id.clone(),
        400,
        EventKind::ProcessFork {
            child_pid: 401,
            is_thread: false,
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        401,
        EventKind::ProcessExec {
            process: Box::new(ProcessInfo {
                pid: 401,
                comm: "make".to_string(),
                argv: vec!["make".to_string(), "test".to_string()],
                ..ProcessInfo::default()
            }),
        },
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        401,
        EventKind::FileOpen {
            path: "/home/dev/project/target/x".to_string(),
            write: true,
        },
    ))
    .expect("write");
    // A decision that allowed everything is not an intervention: the
    // interruption budget holds for the log too.
    log.record(&decision(
        Action::FileOpen {
            path: "/tmp/build".to_string(),
            write: false,
        },
        "build.reports.writes",
        Decision::Allow,
    ))
    .expect("write");
    log.record(&Event::new(
        session.session_id.clone(),
        400,
        EventKind::SessionEnd {
            exit_code: Some(0),
            process_count: 2,
        },
    ))
    .expect("write");
    drop(log);

    let text = std::fs::read_to_string(&path).expect("read the log back");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "start and end only:\n{text}");
    assert!(lines[0].contains("started"), "{text}");
    assert!(lines[1].contains("ended: exit=0"), "{text}");
}

#[test]
fn the_log_file_is_private_to_its_owner() {
    let dir = temp_dir();
    let path = dir.path().join("mode.log");
    let mut log = SessionLog::open(&path).expect("open the log");
    log.record(&Event::new(
        SessionId::from("afw-x"),
        1,
        EventKind::SessionEnd {
            exit_code: Some(0),
            process_count: 1,
        },
    ))
    .expect("write");
    drop(log);

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a session log holds command lines; no other local user may read it"
    );
}

#[test]
fn an_open_of_an_existing_log_appends_and_never_truncates() {
    let dir = temp_dir();
    let path = dir.path().join("append.log");
    let first = SessionId::from("afw-first");
    {
        let mut log = SessionLog::open(&path).expect("open the log");
        log.record(&Event::new(
            first.clone(),
            1,
            EventKind::SessionEnd {
                exit_code: Some(0),
                process_count: 1,
            },
        ))
        .expect("write");
    }
    {
        let mut log = SessionLog::open(&path).expect("open the log again");
        log.record(&Event::new(
            SessionId::from("afw-second"),
            1,
            EventKind::SessionEnd {
                exit_code: Some(1),
                process_count: 1,
            },
        ))
        .expect("write");
    }
    let text = std::fs::read_to_string(&path).expect("read the log");
    assert!(text.contains("afw-first"), "{text}");
    assert!(text.contains("afw-second"), "{text}");
}

#[test]
fn the_default_directory_follows_the_xdg_state_home_convention() {
    // The choice is the point (docs/DECISIONS.md, 2026-09-01): logs are
    // XDG state, next to consent in XDG config and the outbox in XDG data.
    std::env::set_var("XDG_STATE_HOME", "/tmp/afw-state-home");
    assert_eq!(
        SessionLog::default_dir(),
        std::path::Path::new("/tmp/afw-state-home")
            .join("agent-firewall")
            .join("sessions")
    );
    assert_eq!(
        SessionLog::default_path("afw-1"),
        std::path::Path::new("/tmp/afw-state-home")
            .join("agent-firewall")
            .join("sessions")
            .join("afw-1.log")
    );
    std::env::remove_var("XDG_STATE_HOME");

    // Without the variable, the default is ~/.local/state, the XDG default
    // of the state class.
    std::env::set_var("HOME", "/home/tester");
    assert_eq!(
        SessionLog::default_dir(),
        std::path::Path::new("/home/tester/.local/state/agent-firewall/sessions")
    );
    std::env::remove_var("HOME");
}

#[test]
fn the_time_stamps_are_utc_iso8601() {
    let session = session_meta();
    let mut event = Event::new(
        session.session_id.clone(),
        1,
        EventKind::SessionEnd {
            exit_code: Some(0),
            process_count: 1,
        },
    );
    event.ts = 1_800_000_123_456_789_012;
    // 1_800_000_123 seconds after the epoch is 2027-01-15T08:02:03.456Z
    // (checked against `datetime.fromtimestamp`), and the line keeps the
    // millisecond part.
    let line = SessionLog::line_for(&event).expect("a line");
    assert!(
        line.starts_with("2027-01-15T08:02:03.456Z "),
        "the stamp is UTC ISO-8601 with milliseconds: {line}"
    );
}

#[test]
fn a_hostile_command_line_cannot_write_control_characters_into_the_log() {
    let mut session = session_meta();
    session.command = vec![
        "bash\u{1b}[2J".to_string(),
        "-c".to_string(),
        "rm -rf /".to_string(),
    ];
    let event = Event::new(
        session.session_id.clone(),
        1,
        EventKind::SessionStart {
            meta: Box::new(session),
            capabilities: Vec::new(),
        },
    );
    let line = SessionLog::line_for(&event).expect("a line");
    assert!(!line.contains('\u{1b}'), "{line}");
}

/// A destination the test can read back, like the one of `tests/trace.rs`.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("lock").clone()).expect("text")
    }
}

#[test]
fn a_log_and_a_trace_of_one_session_name_the_same_rules() {
    // The log is the human-readable sibling of the trace: the rule that the
    // trace records in JSON is the rule the log names in text.
    let dir = temp_dir();
    let shared = Shared::default();
    let mut log = SessionLog::to_writer(shared.clone(), &dir.path().join("peer.log"));
    let mut trace = TraceWriter::to_writer(Vec::new(), Retention::All);
    let event = decision(
        Action::Exec {
            exe: Some("/usr/bin/psql".to_string()),
            program: "psql".to_string(),
            argv: vec!["psql".to_string()],
            cwd: None,
            env: Default::default(),
        },
        "database.destructive.drop-database",
        Decision::Deny,
    );
    log.record(&event).expect("write");
    trace.record(&event).expect("write");

    let log_text = shared.text();
    assert!(
        log_text.contains("rule=database.destructive.drop-database"),
        "{log_text}"
    );
    assert!(
        log_text.contains("decision deny"),
        "the line names what the engine decided:\n{log_text}"
    );
}
