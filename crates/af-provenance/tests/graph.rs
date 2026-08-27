//! Tests of the causal process graph.

use af_core::{
    Decision, Event, EventKind, Pid, ProcessInfo, ProvenanceView, RiskLevel, RuleMatch, SessionId,
    SessionMeta, Verdict,
};
use af_provenance::ProcessGraph;

/// Makes session metadata with a fixed identifier, so a tree is comparable.
fn session(id: &str, root_pid: Pid) -> SessionMeta {
    let mut meta = SessionMeta::new(vec!["claude".to_string()], "/work".to_string());
    meta.session_id = SessionId::from(id);
    meta.root_pid = root_pid;
    meta
}

fn start(meta: &SessionMeta) -> Event {
    Event::new(
        meta.session_id.clone(),
        meta.root_pid,
        EventKind::SessionStart {
            meta: Box::new(meta.clone()),
            capabilities: Vec::new(),
        },
    )
}

fn fork(meta: &SessionMeta, parent: Pid, child: Pid) -> Event {
    Event::new(
        meta.session_id.clone(),
        parent,
        EventKind::ProcessFork {
            child_pid: child,
            is_thread: false,
        },
    )
}

fn thread(meta: &SessionMeta, parent: Pid, child: Pid) -> Event {
    Event::new(
        meta.session_id.clone(),
        parent,
        EventKind::ProcessFork {
            child_pid: child,
            is_thread: true,
        },
    )
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

fn exec(meta: &SessionMeta, info: ProcessInfo) -> Event {
    Event::new(
        meta.session_id.clone(),
        info.pid,
        EventKind::ProcessExec {
            process: Box::new(info),
        },
    )
}

fn exit(meta: &SessionMeta, pid: Pid, code: i32) -> Event {
    Event::new(
        meta.session_id.clone(),
        pid,
        EventKind::ProcessExit {
            code: Some(code),
            signal: None,
        },
    )
}

fn verdict(decision: Decision, risk: RiskLevel, rule: &str) -> Verdict {
    Verdict::from_matches(vec![RuleMatch {
        rule_id: rule.to_string(),
        title: rule.to_string(),
        category: "database".to_string(),
        risk,
        decision,
        reason: "test".to_string(),
    }])
}

fn decision(meta: &SessionMeta, pid: Pid, verdict: Verdict, ancestry: Vec<ProcessInfo>) -> Event {
    Event::new(
        meta.session_id.clone(),
        pid,
        EventKind::PolicyDecision {
            action: Box::new(af_core::Action::Exec {
                exe: Some("/usr/bin/psql".to_string()),
                program: "psql".to_string(),
                argv: vec!["psql".to_string(), "-c".to_string()],
                cwd: Some("/work".to_string()),
                env: Default::default(),
            }),
            verdict: Box::new(verdict),
            ancestry,
        },
    )
}

/// Builds the chain of the demo: claude -> bash -> migrate.sh -> psql.
fn demo() -> (SessionMeta, Vec<Event>) {
    let meta = session("afw-1a2b", 1000);
    let events = vec![
        start(&meta),
        fork(&meta, 1000, 1001),
        exec(
            &meta,
            process(
                1001,
                1000,
                "/usr/bin/bash",
                &["bash", "-c", "./migrate.sh"],
                11,
            ),
        ),
        fork(&meta, 1001, 1002),
        exec(
            &meta,
            process(1002, 1001, "/work/migrate.sh", &["/work/migrate.sh"], 12),
        ),
        fork(&meta, 1002, 1003),
        exec(
            &meta,
            process(
                1003,
                1002,
                "/usr/bin/psql",
                &["psql", "-c", "DROP DATABASE customer_prod"],
                13,
            ),
        ),
        decision(
            &meta,
            1003,
            verdict(
                Decision::ApprovalRequired,
                RiskLevel::ApprovalRequired,
                "database.destructive.drop-database",
            ),
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
    ];
    (meta, events)
}

fn build(events: &[Event], meta: &SessionMeta) -> ProcessGraph {
    let mut graph = ProcessGraph::new(meta);
    for event in events {
        graph.apply(event);
    }
    graph
}

#[test]
fn tree_of_the_demo_session() {
    let (meta, events) = demo();
    let graph = build(&events, &meta);
    let expected = concat!(
        "afw-1a2b (root)\n",
        "└─ claude [pid 1000]\n",
        "   └─ bash -c ./migrate.sh [pid 1001]\n",
        "      └─ migrate.sh [pid 1002]\n",
        "         └─ psql -c DROP DATABASE customer_prod [pid 1003]  ✖ approval-required"
    );
    assert_eq!(graph.render_tree(), expected);
    assert_eq!(graph.len(), 4);
    assert_eq!(graph.gap_count(), 0);
}

#[test]
fn chain_reaches_the_session_root() {
    let (meta, events) = demo();
    let graph = build(&events, &meta);

    let chain = graph.ancestry(1003);
    let pids: Vec<Pid> = chain.iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![1002, 1001, 1000]);
    assert_eq!(
        graph.chain_summary(1003),
        "claude[1000] -> bash[1001] -> migrate.sh[1002] -> psql[1003]"
    );
    assert!(graph.has_ancestor_program(1003, "bash"));
    assert!(graph.has_ancestor_program(1003, "migrate.sh"));
    assert!(!graph.has_ancestor_program(1003, "psql"));
    assert!(!graph.has_ancestor_program(1000, "claude"));
    assert_eq!(graph.chain_summary(4242), "pid 4242 (unknown)");
}

/// A parent shell often ends before the user looks at a child.
#[test]
fn a_dead_parent_still_carries_the_chain() {
    let (meta, mut events) = demo();
    events.push(exit(&meta, 1002, 0));
    events.push(exit(&meta, 1001, 0));
    let graph = build(&events, &meta);

    let pids: Vec<Pid> = graph.ancestry(1003).iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![1002, 1001, 1000]);
    assert_eq!(graph.len(), 4, "an exit never removes a process");
    assert!(graph.has_ended(1001));
    assert_eq!(graph.exit_status(1001).and_then(|s| s.code), Some(0));
    assert!(!graph.has_ended(1003));
    assert_eq!(
        graph.render_tree().lines().count(),
        5,
        "the tree still shows the dead parents"
    );
}

/// Linux gives the same identifier to a new process later.
#[test]
fn identifier_reuse_keeps_the_two_chains_apart() {
    let meta = session("afw-reuse", 1);
    let events = vec![
        start(&meta),
        exec(&meta, process(10, 1, "/usr/bin/bash", &["bash"], 5)),
        exec(&meta, process(20, 1, "/usr/bin/zsh", &["zsh"], 6)),
        // First process 100: a child of bash.
        fork(&meta, 10, 100),
        exec(
            &meta,
            process(100, 10, "/usr/bin/git", &["git", "push"], 50),
        ),
        exit(&meta, 100, 0),
        // Second process 100: a child of zsh, with another start time.
        fork(&meta, 20, 100),
        exec(
            &meta,
            process(100, 20, "/usr/bin/psql", &["psql", "-c", "DROP"], 99),
        ),
    ];
    let graph = build(&events, &meta);

    assert_eq!(graph.len(), 5, "both processes 100 stay in the graph");
    let now = graph.process(100).expect("the live process");
    assert_eq!(now.program_name(), "psql");
    assert_eq!(now.start_ticks, 99);
    let pids: Vec<Pid> = graph.ancestry(100).iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![20, 1], "the new chain runs through zsh");
    assert!(graph.has_ancestor_program(100, "zsh"));
    assert!(
        !graph.has_ancestor_program(100, "bash"),
        "the old chain must not reach the new process"
    );

    let old = graph
        .process_by_key(&af_core::ProcessKey::new(100, 50))
        .expect("the old process");
    assert_eq!(old.program_name(), "git");
    assert_eq!(old.ppid, Some(10));

    let tree = graph.render_tree();
    assert!(tree.contains("git push [pid 100]"), "{tree}");
    assert!(tree.contains("psql -c DROP [pid 100]"), "{tree}");
}

/// A missing exit event must not join two processes either.
#[test]
fn a_fork_always_makes_a_new_process() {
    let meta = session("afw-fork", 1);
    let events = vec![
        start(&meta),
        exec(&meta, process(10, 1, "/usr/bin/bash", &["bash"], 5)),
        fork(&meta, 10, 100),
        exec(&meta, process(100, 10, "/usr/bin/git", &["git"], 50)),
        // No exit event arrives for the first process 100.
        fork(&meta, 10, 100),
        exec(&meta, process(100, 10, "/usr/bin/psql", &["psql"], 99)),
    ];
    let graph = build(&events, &meta);

    assert_eq!(graph.len(), 4);
    assert_eq!(graph.process(100).expect("live").program_name(), "psql");
    assert!(!graph.has_ended(100));
    assert!(!graph.has_ended(4242), "an unknown process is not ended");
}

/// A process keeps its identity when it replaces its program.
#[test]
fn an_exec_updates_the_node_and_keeps_the_history() {
    let meta = session("afw-exec", 1);
    let events = vec![
        start(&meta),
        exec(&meta, process(10, 1, "/usr/bin/bash", &["bash"], 5)),
        fork(&meta, 10, 11),
        exec(
            &meta,
            process(11, 10, "/usr/bin/bash", &["bash", "./migrate.sh"], 7),
        ),
        // The shell script replaces the shell with itself.
        exec(
            &meta,
            process(11, 10, "/work/migrate.sh", &["migrate.sh"], 7),
        ),
    ];
    let graph = build(&events, &meta);

    assert_eq!(
        graph.len(),
        3,
        "an exec never adds a process: the session root, the shell and the script"
    );
    assert_eq!(graph.history(11), vec!["bash".to_string()]);
    assert_eq!(
        graph.process(11).expect("process").program_name(),
        "migrate.sh"
    );
    let tree = graph.render_tree();
    assert!(tree.contains("bash -> migrate.sh [pid 11]"), "{tree}");
    assert!(
        graph.has_ancestor_program(11, "bash"),
        "the parent shell is still an ancestor"
    );
}

/// The graph must stay usable when the monitor missed the fork.
#[test]
fn an_unknown_parent_hangs_under_the_session_root() {
    let meta = session("afw-gap", 1000);
    let events = vec![
        start(&meta),
        exec(&meta, process(1000, 1, "/usr/bin/claude", &["claude"], 3)),
        // No fork event arrives for 2000, and its parent is unknown.
        exec(&meta, process(2000, 1999, "/usr/bin/psql", &["psql"], 8)),
    ];
    let graph = build(&events, &meta);

    assert_eq!(graph.len(), 2);
    assert_eq!(graph.gap_count(), 1);
    assert!(graph.ancestry(2000).is_empty());
    let tree = graph.render_tree();
    assert_eq!(tree.lines().count(), 3, "{tree}");
    assert!(tree.contains("├─ claude [pid 1000]"), "{tree}");
    assert!(tree.contains("└─ psql [pid 2000]"), "{tree}");
}

/// A late exec event repairs the link.
#[test]
fn the_graph_attaches_a_process_when_it_learns_the_parent() {
    let meta = session("afw-late", 1000);
    let mut graph = ProcessGraph::new(&meta);
    graph.apply(&start(&meta));
    // The decision arrives before the exec of the process.
    graph.apply(&decision(
        &meta,
        2000,
        verdict(Decision::Deny, RiskLevel::Blocked, "git.force-push"),
        Vec::new(),
    ));
    assert_eq!(graph.gap_count(), 1);
    graph.apply(&exec(
        &meta,
        process(2000, 1000, "/usr/bin/git", &["git", "push", "--force"], 9),
    ));

    let pids: Vec<Pid> = graph.ancestry(2000).iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![1000]);
    let tree = graph.render_tree();
    assert!(
        tree.contains("git push --force [pid 2000]  ✖ deny"),
        "{tree}"
    );
}

/// A decision holds its own chain, so a small trace still shows the tree.
#[test]
fn a_decision_rebuilds_a_missing_chain() {
    let meta = session("afw-evidence", 1000);
    let mut graph = ProcessGraph::new(&meta);
    graph.apply(&start(&meta));
    graph.apply(&decision(
        &meta,
        1003,
        verdict(
            Decision::ApprovalRequired,
            RiskLevel::ApprovalRequired,
            "database.destructive.drop-database",
        ),
        vec![
            process(1002, 1001, "/work/migrate.sh", &["migrate.sh"], 12),
            process(1001, 1000, "/usr/bin/bash", &["bash"], 11),
        ],
    ));

    let pids: Vec<Pid> = graph.ancestry(1003).iter().map(|p| p.pid).collect();
    assert_eq!(pids, vec![1002, 1001, 1000]);
    assert_eq!(graph.len(), 4);
}

/// The strongest verdict wins, and the tree stays quiet for an allow.
#[test]
fn the_strongest_verdict_marks_the_process() {
    let meta = session("afw-verdict", 10);
    let mut graph = ProcessGraph::new(&meta);
    graph.apply(&start(&meta));
    graph.apply(&exec(&meta, process(10, 1, "/usr/bin/psql", &["psql"], 3)));
    graph.apply(&decision(&meta, 10, Verdict::allow(), Vec::new()));
    assert!(!graph.render_tree().contains("allow"));

    graph.apply(&decision(
        &meta,
        10,
        verdict(Decision::AllowSession, RiskLevel::Low, "shell.normal"),
        Vec::new(),
    ));
    assert!(graph.render_tree().contains("• allow-session"));

    graph.apply(&decision(
        &meta,
        10,
        verdict(Decision::Terminate, RiskLevel::Blocked, "database.drop"),
        Vec::new(),
    ));
    graph.apply(&decision(
        &meta,
        10,
        verdict(Decision::AllowOnce, RiskLevel::Info, "shell.normal"),
        Vec::new(),
    ));
    assert!(graph.render_tree().contains("✖ terminate"));
    assert_eq!(
        graph.verdict(10).expect("verdict").decision,
        Decision::Terminate
    );
}

/// The same events must always draw the same tree.
#[test]
fn the_tree_is_stable() {
    let (meta, events) = demo();
    let first = build(&events, &meta).render_tree();
    for _ in 0..20 {
        let again = build(&events, &meta);
        assert_eq!(again.render_tree(), first);
        assert_eq!(again.render_tree(), again.render_tree());
    }
}

/// Children sort by creation order, so a wide tree also stays stable.
#[test]
fn children_keep_their_creation_order() {
    let meta = session("afw-wide", 1);
    let mut events = vec![
        start(&meta),
        exec(&meta, process(1, 0, "/usr/bin/bash", &["bash"], 2)),
    ];
    for child in [50, 20, 40, 10, 30] {
        events.push(fork(&meta, 1, child));
        events.push(exec(
            &meta,
            process(child, 1, "/usr/bin/tool", &["tool"], child as u64),
        ));
    }
    let graph = build(&events, &meta);
    let order: Vec<Pid> = graph.processes().iter().map(|p| p.pid).collect();
    assert_eq!(order, vec![1, 50, 20, 40, 10, 30]);

    let tree = graph.render_tree();
    let pids: Vec<&str> = tree
        .lines()
        .skip(2)
        .map(|line| {
            line.split("[pid ")
                .nth(1)
                .unwrap_or("")
                .trim_end_matches(']')
        })
        .collect();
    assert_eq!(pids, vec!["50", "20", "40", "10", "30"]);
}

/// A thread is not a new process.
#[test]
fn a_thread_does_not_become_a_process() {
    let meta = session("afw-thread", 1);
    let events = vec![
        start(&meta),
        exec(&meta, process(1, 0, "/usr/bin/node", &["node"], 2)),
        thread(&meta, 1, 77),
    ];
    let graph = build(&events, &meta);
    assert_eq!(graph.len(), 1);
    assert!(graph.process(77).is_none());
}

/// A rebuilt graph must give the same answers as the live graph.
#[test]
fn from_trace_rebuilds_the_same_graph() {
    let (meta, events) = demo();
    let live = build(&events, &meta);
    let replay = ProcessGraph::from_trace(&events);

    assert_eq!(replay.render_tree(), live.render_tree());
    assert_eq!(replay.len(), live.len());
    assert_eq!(replay.processes(), live.processes());
    assert_eq!(replay.ancestry(1003), live.ancestry(1003));
    assert_eq!(replay.session_id(), live.session_id());
    assert_eq!(replay.session().root_pid, 1000);
}

/// A trace without a session start still gives a usable graph.
#[test]
fn from_trace_works_without_a_session_start() {
    let (meta, events) = demo();
    let without: Vec<Event> = events
        .into_iter()
        .filter(|event| !matches!(event.kind, EventKind::SessionStart { .. }))
        .collect();
    let graph = ProcessGraph::from_trace(&without);

    assert_eq!(graph.session_id().as_str(), meta.session_id.as_str());
    assert_eq!(graph.len(), 3, "the root process has no exec event here");
    assert!(graph.render_tree().starts_with("afw-1a2b (root)"));
}

/// An empty graph holds nothing.
#[test]
fn a_new_graph_is_empty() {
    let meta = session("afw-empty", 1000);
    let graph = ProcessGraph::new(&meta);
    assert!(graph.is_empty());
    assert_eq!(graph.len(), 0);
    assert!(graph.processes().is_empty());
    assert_eq!(graph.render_tree(), "afw-empty (root)");
    assert!(graph.process(1000).is_none());
    assert!(ProcessGraph::from_trace(&[]).is_empty());
}

/// The policy engine reads the graph through the trait of the core crate.
#[test]
fn the_graph_serves_the_provenance_view() {
    let (meta, events) = demo();
    let graph = build(&events, &meta);
    let view: &dyn ProvenanceView = &graph;

    assert_eq!(view.process(1003).expect("process").program_name(), "psql");
    let ancestry = view.ancestry(1003);
    let process = view.process(1003).expect("process");
    let action = af_core::Action::Exec {
        exe: Some("/usr/bin/psql".to_string()),
        program: "psql".to_string(),
        argv: vec!["psql".to_string()],
        cwd: None,
        env: Default::default(),
    };
    let ctx = af_core::EvalContext::new(&meta, &action, &process, &ancestry);
    assert!(ctx.has_ancestor("bash"));
    assert_eq!(ctx.parent().expect("parent").pid, 1002);
    assert!(view.process(9999).is_none());
}

/// A control character of a monitored program must not reach the terminal.
#[test]
fn the_tree_removes_control_characters() {
    let meta = session("afw-escape", 1);
    let events = vec![
        start(&meta),
        exec(
            &meta,
            process(
                1,
                0,
                "/usr/bin/bash",
                &["bash", "-c", "echo \u{1b}[31mred"],
                2,
            ),
        ),
    ];
    let graph = build(&events, &meta);
    let tree = graph.render_tree();
    assert!(!tree.contains('\u{1b}'), "{tree}");
    assert!(tree.contains('·'), "{tree}");
}

/// A session end closes every process that is still open.
#[test]
fn a_session_end_closes_every_process() {
    let (meta, mut events) = demo();
    events.push(Event::new(
        meta.session_id.clone(),
        1000,
        EventKind::SessionEnd {
            exit_code: Some(0),
            process_count: 4,
        },
    ));
    let graph = build(&events, &meta);
    assert!(graph.has_ended(1000));
    assert!(graph.has_ended(1003));
    assert_eq!(graph.len(), 4);
}
