//! End-to-end tests of sample packaging: what travels, what is dropped, and
//! what is pseudonymized, over one synthetic session with every scope
//! granted. If a secret, a baseline remote, a session identifier or a raw
//! process identifier reaches the sample text here, the packaging is wrong.

use std::collections::BTreeMap;

use af_core::{
    Action, ApprovalOutcome, Decision, Event, EventKind, IdentifiedAgent, InputStream,
    MonitorCapability, ProcessInfo, RiskLevel, RuleMatch, SessionId, SessionMeta, TamperKind,
    Verdict,
};
use af_telemetry::{build_samples, list_samples, write_sample, Consent, Options, Scope};

/// The time of the first event of the made session.
const START: u64 = 1_700_000_000_000_000_000;

/// Makes an event of the made session at a given offset in milliseconds.
fn event(pid: i32, at_ms: u64, kind: EventKind) -> Event {
    let mut event = Event::new(SessionId::from("afw-test-secret"), pid, kind);
    event.ts = START + at_ms * 1_000_000;
    event
}

/// Makes a session metadata of the made session.
fn meta() -> SessionMeta {
    let mut meta = SessionMeta::new(vec!["claude".to_string()], "/home/dev/proj".to_string());
    meta.session_id = SessionId::from("afw-test-secret");
    meta.started_at = START;
    meta.root_pid = 41001;
    meta.monitor_pid = 41000;
    let mut baseline = BTreeMap::new();
    baseline.insert(
        "git_remotes".to_string(),
        ["https://github.com/acme/private-app.git".to_string()]
            .into_iter()
            .collect(),
    );
    meta.baseline = baseline;
    meta.detection = Some(IdentifiedAgent {
        name: "claude-code".to_string(),
        confidence: 0.95,
        signals: vec![af_core::DetectionSignal {
            detector: "known_executables".to_string(),
            agent: "claude-code".to_string(),
            detail: "the program name is `claude`".to_string(),
            confidence: 0.95,
        }],
    });
    meta
}

/// Makes a process record of the made session.
fn process(pid: i32, ppid: Option<i32>, exe: &str, argv: &[&str]) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        exe: Some(exe.to_string()),
        comm: exe.rsplit('/').next().unwrap_or(exe).to_string(),
        argv: argv.iter().map(|word| word.to_string()).collect(),
        cwd: Some("/home/dev/proj".to_string()),
        env: BTreeMap::new(),
        ..Default::default()
    }
}

/// The verdict of the denied `DROP DATABASE`.
fn drop_verdict() -> Verdict {
    Verdict {
        decision: Decision::Deny,
        risk: RiskLevel::ApprovalRequired,
        quarantine: false,
        matches: vec![RuleMatch {
            rule_id: "database.destructive.drop-database".to_string(),
            title: "a statement drops a whole database".to_string(),
            category: "database".to_string(),
            risk: RiskLevel::ApprovalRequired,
            decision: Decision::Deny,
            reason: "the command line of psql holds DROP DATABASE customer_prod".to_string(),
            quarantine: false,
        }],
    }
}

/// Makes the events of the made session: one denied chain that ends in the
/// dangerous statement, with a secret on the command line, in the
/// environment, on standard input and in the baseline.
fn session_events() -> Vec<Event> {
    vec![
        event(
            41000,
            0,
            EventKind::SessionStart {
                meta: Box::new(meta()),
                capabilities: vec![MonitorCapability::available("exec_interception")],
            },
        ),
        event(
            41001,
            1,
            EventKind::ProcessExec {
                process: Box::new(process(
                    41001,
                    Some(1),
                    "/home/dev/.nvm/versions/node/v22/bin/claude",
                    &["claude"],
                )),
            },
        ),
        event(
            41001,
            2,
            EventKind::ProcessFork {
                child_pid: 41100,
                is_thread: false,
            },
        ),
        {
            let mut shell = process(
                41100,
                Some(41001),
                "/usr/bin/bash",
                &["bash", "-c", "psql -c 'DROP DATABASE customer_prod'"],
            );
            shell.env.insert(
                "API_TOKEN".to_string(),
                "sk-ant-supersecret123456".to_string(),
            );
            event(
                41100,
                3,
                EventKind::ProcessExec {
                    process: Box::new(shell),
                },
            )
        },
        event(
            41100,
            4,
            EventKind::ProcessExec {
                process: Box::new(process(
                    41101,
                    Some(41100),
                    "/usr/bin/psql",
                    &[
                        "psql",
                        "-h",
                        "db.prod.internal",
                        "--set=db_password=hunter2",
                        "-c",
                        "DROP DATABASE customer_prod",
                    ],
                )),
            },
        ),
        event(
            41101,
            5,
            EventKind::StdinWrite {
                stream: InputStream::Stdin,
                data: "password=hunter2; DROP DATABASE customer_prod;".to_string(),
            },
        ),
        event(
            41101,
            6,
            EventKind::PolicyDecision {
                action: Box::new(Action::Exec {
                    exe: Some("/usr/bin/psql".to_string()),
                    program: "psql".to_string(),
                    argv: vec![
                        "psql".to_string(),
                        "-h".to_string(),
                        "db.prod.internal".to_string(),
                        "-c".to_string(),
                        "DROP DATABASE customer_prod".to_string(),
                    ],
                    cwd: Some("/home/dev/proj".to_string()),
                    env: BTreeMap::new(),
                }),
                verdict: Box::new(drop_verdict()),
                ancestry: vec![
                    process(41100, Some(41001), "/usr/bin/bash", &["bash"]),
                    process(
                        41001,
                        Some(1),
                        "/home/dev/.nvm/versions/node/v22/bin/claude",
                        &["claude"],
                    ),
                ],
            },
        ),
        event(
            41101,
            7,
            EventKind::ApprovalRequested {
                action: Box::new(Action::Exec {
                    exe: Some("/usr/bin/psql".to_string()),
                    program: "psql".to_string(),
                    argv: vec!["psql".to_string()],
                    cwd: None,
                    env: BTreeMap::new(),
                }),
                rule_id: "database.destructive.drop-database".to_string(),
            },
        ),
        event(
            41101,
            8,
            EventKind::ApprovalResolved {
                rule_id: "database.destructive.drop-database".to_string(),
                outcome: ApprovalOutcome::Deny,
                waited_ms: 1200,
            },
        ),
        event(
            41001,
            9,
            EventKind::SessionEnd {
                exit_code: Some(3),
                process_count: 3,
            },
        ),
    ]
}

/// The options of the made machine.
fn options() -> Options {
    Options {
        window: 20,
        home: Some("/home/dev".to_string()),
        host: Some("box1".to_string()),
    }
}

/// Every scope granted.
fn all_scopes() -> Consent {
    let mut consent = Consent::off();
    for scope in Scope::ALL {
        consent.grant(*scope);
    }
    consent
}

#[test]
fn a_denied_action_becomes_one_sample_with_both_reasons() {
    let samples = build_samples(&session_events(), &all_scopes(), &options());
    assert_eq!(samples.len(), 1, "the burst of the denial is one sample");
    let sample = &samples[0];
    let kinds: Vec<&str> = sample.reasons.iter().map(|r| r.kind.as_str()).collect();
    assert!(
        kinds.contains(&"policy_decision"),
        "the decision triggers: {kinds:?}"
    );
    assert!(
        kinds.contains(&"approval_requested"),
        "the question triggers: {kinds:?}"
    );
    assert_eq!(
        sample.rules(),
        vec![
            "database.destructive.drop-database",
            "database.destructive.drop-database"
        ],
        "each trigger names the rule that caused it"
    );
}

#[test]
fn no_secret_baseline_session_id_or_raw_pid_reaches_the_sample_text() {
    let samples = build_samples(&session_events(), &all_scopes(), &options());
    let text = serde_json::to_string(&samples).expect("encode the samples");

    // The secrets of every shape: an environment value, a command-line
    // assignment, a standard-input assignment.
    assert!(
        !text.contains("hunter2"),
        "the sample must not hold a secret:\n{text}"
    );
    assert!(
        !text.contains("sk-ant-supersecret123456"),
        "an environment value must never travel:\n{text}"
    );
    // The baseline names a private repository, and no rule needs it here.
    assert!(
        !text.contains("acme/private-app"),
        "the baseline must not travel:\n{text}"
    );
    // The session identifier is pseudonymized, the raw pids are references.
    assert!(
        !text.contains("afw-test-secret"),
        "the session id must not travel:\n{text}"
    );
    for pid in ["41000", "41001", "41100", "41101"] {
        assert!(
            !text.contains(pid),
            "the raw pid {pid} must not travel:\n{text}"
        );
    }
    // The home directory and the machine name are pseudonymized.
    assert!(
        !text.contains("/home/dev"),
        "the home directory must not travel:\n{text}"
    );
    assert!(
        !text.contains("box1"),
        "the host name must not travel:\n{text}"
    );
}

#[test]
fn the_sample_carries_the_redacted_payload_it_promises() {
    let samples = build_samples(&session_events(), &all_scopes(), &options());
    let text = serde_json::to_string(&samples).expect("encode the samples");

    // The rule, the decision and the reason travel.
    assert!(text.contains("database.destructive.drop-database"));
    assert!(text.contains("\"decision\":\"deny\""));
    // The command line of the shell travels, with the credential redacted
    // in place and the dangerous statement intact for the researcher.
    assert!(text.contains("DROP DATABASE customer_prod"));
    assert!(text.contains("db_password=<redacted>"));
    // The environment name travels, its value never.
    assert!(text.contains("\"API_TOKEN\":\"<redacted>\""));
    // The standard input travels with the assignment redacted.
    assert!(text.contains("password=<redacted>"));
    // The identity and the tree travel, pseudonymized.
    assert!(text.contains("claude-code"));
    assert!(text.contains("<home>/.nvm/versions/node/v22/bin/claude"));
    assert!(text.contains("\"reference\":\"p"));
    // The pseudonymized session reference has the documented shape.
    assert!(text.contains("\"session\":\"s-"));
}

#[test]
fn each_scope_gates_its_own_payload() {
    let events = session_events();

    // Tree alone: the tree and the executable paths, no command lines, no
    // content, no environment, no identity.
    let mut tree_only = Consent::off();
    tree_only.grant(Scope::Tree);
    let samples = build_samples(&events, &tree_only, &options());
    let text = serde_json::to_string(&samples).expect("encode");
    assert!(text.contains("\"tree\":"));
    assert!(text.contains("<home>/.nvm/versions/node/v22/bin/claude"));
    assert!(
        !text.contains("argv"),
        "no command line without the actions scope"
    );
    assert!(
        !text.contains("db.prod.internal"),
        "no action target without the actions scope"
    );
    assert!(
        !text.contains("\"data\""),
        "no observed content without the content scope"
    );
    assert!(
        !text.contains("claude-code\""),
        "no identity without the identity scope"
    );

    // Actions alone: what happened, with no tree structure around it.
    let mut actions_only = Consent::off();
    actions_only.grant(Scope::Actions);
    let samples = build_samples(&events, &actions_only, &options());
    let text = serde_json::to_string(&samples).expect("encode");
    assert!(text.contains("DROP DATABASE customer_prod"));
    assert!(!text.contains("\"tree\""), "no tree without the tree scope");
    assert!(
        !text.contains(".nvm/"),
        "no executable paths without the tree scope"
    );

    // Content alone: the standard input, with nothing else around it.
    let mut content_only = Consent::off();
    content_only.grant(Scope::Content);
    let samples = build_samples(&events, &content_only, &options());
    let text = serde_json::to_string(&samples).expect("encode");
    assert!(
        text.contains("password=<redacted>; DROP DATABASE customer_prod;"),
        "the content scope carries the redacted input:\n{text}"
    );
    assert!(
        !text.contains("db.prod.internal"),
        "no command line without the actions scope"
    );

    // No scope at all: the bare reasons. The caller already checked that
    // the user granted something, so this is the smallest honest sample.
    let samples = build_samples(&events, &Consent::off(), &options());
    assert_eq!(samples.len(), 1);
    let text = serde_json::to_string(&samples).expect("encode");
    assert!(text.contains("database.destructive.drop-database"));
    assert!(!text.contains("\"tree\""));
    assert!(!text.contains("argv"));
    assert!(!text.contains("\"data\""));
}

#[test]
fn tamper_and_discrepancy_events_are_triggers_too() {
    let mut events = vec![
        event(
            41000,
            0,
            EventKind::SessionStart {
                meta: Box::new(meta()),
                capabilities: Vec::new(),
            },
        ),
        event(
            41001,
            1,
            EventKind::ProcessExec {
                process: Box::new(process(41001, Some(1), "/usr/bin/claude", &["claude"])),
            },
        ),
    ];
    events.push(event(
        41100,
        2,
        EventKind::SignalSend {
            target: 41000,
            signal: 9,
        },
    ));
    events.push(event(
        41100,
        3,
        EventKind::Tamper {
            kind: TamperKind::KilledSubtreeReturned,
            detail: "the killed program /home/dev/proj/evil came back under p2".to_string(),
        },
    ));
    let samples = build_samples(&events, &all_scopes(), &options());
    assert_eq!(samples.len(), 1, "the adjacent facts merge into one sample");
    let kinds: Vec<&str> = samples[0].reasons.iter().map(|r| r.kind.as_str()).collect();
    assert!(kinds.contains(&"signal_send"), "{kinds:?}");
    assert!(kinds.contains(&"tamper"), "{kinds:?}");
    // The evidence line travels under the actions scope, scrubbed.
    let text = serde_json::to_string(&samples).expect("encode");
    assert!(
        text.contains("<home>/proj/evil"),
        "the path is pseudonymized:\n{text}"
    );
}

#[test]
fn a_quiet_session_makes_no_sample() {
    let events = vec![
        event(
            41000,
            0,
            EventKind::SessionStart {
                meta: Box::new(meta()),
                capabilities: Vec::new(),
            },
        ),
        event(
            41001,
            1,
            EventKind::ProcessExec {
                process: Box::new(process(41001, Some(1), "/usr/bin/true", &["true"])),
            },
        ),
        event(
            41001,
            2,
            EventKind::SessionEnd {
                exit_code: Some(0),
                process_count: 1,
            },
        ),
    ];
    let samples = build_samples(&events, &all_scopes(), &options());
    assert!(
        samples.is_empty(),
        "nothing suspicious happened, nothing is packaged"
    );
}

#[test]
fn far_apart_triggers_make_two_samples_with_a_small_window() {
    let mut events = vec![event(
        41000,
        0,
        EventKind::SessionStart {
            meta: Box::new(meta()),
            capabilities: Vec::new(),
        },
    )];
    for step in 0..30 {
        let pid = 42000i32 + step as i32;
        events.push(event(
            41001,
            step + 1,
            EventKind::ProcessFork {
                child_pid: pid,
                is_thread: false,
            },
        ));
    }
    // One trigger at the start, one at the end: with a window of two they
    // cannot touch each other.
    events[1] = event(
        41001,
        1,
        EventKind::SignalSend {
            target: 41000,
            signal: 9,
        },
    );
    events[30] = event(
        41001,
        30,
        EventKind::SignalSend {
            target: 41000,
            signal: 9,
        },
    );

    let options = Options {
        window: 2,
        ..options()
    };
    let samples = build_samples(&events, &all_scopes(), &options);
    assert_eq!(samples.len(), 2, "two far apart triggers, two samples");
    for sample in &samples {
        assert!(
            sample.events.len() <= 5,
            "the window carries the trigger and its context"
        );
    }
}

#[test]
fn the_tree_names_real_files_by_hash_and_the_outbox_counts_them() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let program = dir.path().join("agent-sim");
    std::fs::write(&program, b"#!/bin/sh\necho sim\n").expect("write the program");

    let events = vec![
        event(
            41000,
            0,
            EventKind::SessionStart {
                meta: Box::new(meta()),
                capabilities: Vec::new(),
            },
        ),
        event(
            41001,
            1,
            EventKind::ProcessExec {
                process: Box::new(ProcessInfo {
                    pid: 41001,
                    ppid: Some(1),
                    exe: Some(program.display().to_string()),
                    comm: "agent-sim".to_string(),
                    argv: vec!["agent-sim".to_string()],
                    ..Default::default()
                }),
            },
        ),
        event(
            41001,
            2,
            EventKind::SignalSend {
                target: 41000,
                signal: 9,
            },
        ),
    ];
    let mut consent = Consent::off();
    consent.grant(Scope::Tree);
    let samples = build_samples(&events, &consent, &options());
    assert_eq!(samples.len(), 1);
    let node = samples[0]
        .tree
        .iter()
        .find(|node| node.comm == "agent-sim")
        .expect("the simulated agent is in the tree");
    let digest = af_telemetry::sha256_hex(&af_telemetry::sha256_digest(b"#!/bin/sh\necho sim\n"));
    assert_eq!(
        node.exe_hash.as_deref(),
        Some(format!("sha256:{digest}").as_str()),
        "the hash names the real program file"
    );

    // The outbox counts the samples of one session.
    let outbox = dir.path().join("outbox");
    let first = write_sample(&outbox, &samples[0]).expect("write the first");
    let second = write_sample(&outbox, &samples[0]).expect("write the second");
    assert!(first.display().to_string().ends_with("-001.json"));
    assert!(second.display().to_string().ends_with("-002.json"));
    let listed = list_samples(&outbox).expect("list the outbox");
    assert_eq!(listed.len(), 2);
    let back: af_telemetry::Sample =
        serde_json::from_str(&std::fs::read_to_string(&first).expect("read back"))
            .expect("a sample file is a sample");
    assert_eq!(back, samples[0]);
}

/// A sample file is created for its owner only.
///
/// A sample names the machine and its sessions even after redaction, and it
/// sits in a shared home's data directory, so the file must carry the mode
/// 0600 whatever the umask of the command that wrote it is.
#[test]
fn a_sample_file_is_created_for_its_owner_only() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().expect("temporary directory");
    let samples = build_samples(&session_events(), &all_scopes(), &options());
    let path = write_sample(dir.path(), &samples[0]).expect("write the sample");

    let mode = std::fs::metadata(&path).expect("stat").mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a sample names this machine's sessions; no other local user may read it"
    );
}
