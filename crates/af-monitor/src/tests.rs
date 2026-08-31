//! Tests that launch real short-lived processes.
//!
//! Every test that starts a process takes [`SESSION_LOCK`] first. The monitor
//! reaps every child of the test program, so two sessions at the same time
//! would take the children of each other.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use af_core::{Action, Event, EventKind, Pid, ProcessInfo, SessionMeta};

use crate::{
    inspect, procfs, InputSnapshot, Intercept, Monitor, MonitorConfig, MonitorHandler,
    SessionOutcome, SyscallFilter,
};

/// Keeps two sessions from running at the same time.
static SESSION_LOCK: Mutex<()> = Mutex::new(());

/// Takes the session lock, also after another test failed.
fn lock() -> MutexGuard<'static, ()> {
    SESSION_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// A handler that keeps everything and can stop chosen programs.
#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
    execs: Vec<ProcessInfo>,
    ancestry: HashMap<Pid, Vec<Pid>>,
    inputs: HashMap<String, InputSnapshot>,
    deny: Option<String>,
    terminate: Option<String>,
    /// Every action that the kernel filter held, in the order it held them.
    actions: Vec<Action>,
    /// A file open whose path holds this text is refused.
    refuse_path: Option<String>,
    /// A connection to this port is refused.
    refuse_port: Option<u16>,
}

impl Recorder {
    /// Makes a handler that stops one program before it runs.
    fn denying(program: &str) -> Self {
        Self {
            deny: Some(program.to_string()),
            ..Default::default()
        }
    }

    /// Makes a handler that ends the session at one program.
    fn terminating(program: &str) -> Self {
        Self {
            terminate: Some(program.to_string()),
            ..Default::default()
        }
    }

    /// Returns every event of one kind.
    fn of_kind(&self, label: &str) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|event| event.kind_label() == label)
            .collect()
    }

    /// Makes a handler that refuses every open of a path with this text.
    fn refusing_path(text: &str) -> Self {
        Self {
            refuse_path: Some(text.to_string()),
            ..Default::default()
        }
    }

    /// Makes a handler that refuses every connection to one port.
    fn refusing_port(port: u16) -> Self {
        Self {
            refuse_port: Some(port),
            ..Default::default()
        }
    }

    /// Returns the identifier of the process of the first exec event.
    fn root_pid(&self) -> Pid {
        self.execs.first().expect("at least one exec").pid
    }

    /// Returns every file open that the kernel filter held.
    fn opens(&self) -> Vec<(&str, bool)> {
        self.actions
            .iter()
            .filter_map(|action| match action {
                Action::FileOpen { path, write } => Some((path.as_str(), *write)),
                _ => None,
            })
            .collect()
    }

    /// Returns every connection that the kernel filter held.
    fn connects(&self) -> Vec<(&str, u16)> {
        self.actions
            .iter()
            .filter_map(|action| match action {
                Action::NetworkConnect { addr, port, .. } => Some((addr.as_str(), *port)),
                _ => None,
            })
            .collect()
    }

    /// Returns true when one held open names a path with this text.
    fn opened(&self, text: &str, write: bool) -> bool {
        self.opens()
            .iter()
            .any(|(path, is_write)| path.contains(text) && *is_write == write)
    }
}

impl MonitorHandler for Recorder {
    fn on_event(&mut self, event: Event) {
        self.events.push(event);
    }

    fn on_exec(
        &mut self,
        process: &ProcessInfo,
        ancestry: &[Pid],
        input: Option<&InputSnapshot>,
        _sensed: &crate::ExecSensed,
        _tree: &mut dyn crate::TreeControl,
    ) -> Intercept {
        let program = process.program_name().to_string();
        self.execs.push(process.clone());
        self.ancestry.insert(process.pid, ancestry.to_vec());
        if let Some(snapshot) = input {
            self.inputs.insert(program.clone(), snapshot.clone());
        }
        if self.deny.as_deref() == Some(program.as_str()) {
            return Intercept::Deny;
        }
        if self.terminate.as_deref() == Some(program.as_str()) {
            return Intercept::TerminateSession;
        }
        Intercept::Continue
    }

    fn on_syscall(
        &mut self,
        _pid: Pid,
        action: &Action,
        _ancestry: &[Pid],
        _tree: &mut dyn crate::TreeControl,
    ) -> Intercept {
        self.actions.push(action.clone());
        match action {
            Action::FileOpen { path, .. } => {
                if let Some(text) = self.refuse_path.as_deref() {
                    if path.contains(text) {
                        return Intercept::Refuse;
                    }
                }
            }
            Action::NetworkConnect { port, .. } if self.refuse_port == Some(*port) => {
                return Intercept::Refuse;
            }
            _ => {}
        }
        Intercept::Continue
    }
}

/// Runs one session on another thread and fails when it takes too long.
fn run_config(
    config: MonitorConfig,
    handler: Recorder,
    seconds: u64,
) -> (SessionOutcome, Recorder) {
    let _guard = lock();
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut handler = handler;
        let session = SessionMeta::new(config.command.clone(), ".".to_string());
        let result = Monitor::run(&config, &session, &mut handler);
        let _ = sender.send((result, handler));
    });
    let (result, handler) = receiver
        .recv_timeout(Duration::from_secs(seconds))
        .expect("the monitor did not finish in time");
    worker.join().expect("the monitor thread failed");
    (result.expect("the monitor reported an error"), handler)
}

/// Runs one command under the monitor with the standard settings.
fn run_session(command: &[&str], handler: Recorder, seconds: u64) -> (SessionOutcome, Recorder) {
    let config = MonitorConfig::new(command.iter().map(|word| word.to_string()).collect());
    run_config(config, handler, seconds)
}

/// Runs a shell command under the monitor.
fn run_shell(script: &str, handler: Recorder, seconds: u64) -> (SessionOutcome, Recorder) {
    run_session(&["/bin/sh", "-c", script], handler, seconds)
}

/// Runs a shell command with one filter mode.
fn run_filtered(
    script: &str,
    filter: SyscallFilter,
    handler: Recorder,
    seconds: u64,
) -> (SessionOutcome, Recorder) {
    let command = ["/bin/sh", "-c", script]
        .iter()
        .map(|word| word.to_string())
        .collect();
    let config = MonitorConfig {
        syscall_filter: filter,
        ..MonitorConfig::new(command)
    };
    run_config(config, handler, seconds)
}

#[test]
fn simple_session_reports_exec_and_exit() {
    let (outcome, handler) = run_shell("true", Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.signal, None);
    assert!(!outcome.terminated_by_firewall);
    assert_eq!(outcome.process_count, 1);
    assert!(outcome.is_success());

    // The monitor never makes a session event. The launcher owns those.
    assert!(handler.of_kind("session_start").is_empty());
    assert!(handler.of_kind("session_end").is_empty());

    let execs = handler.of_kind("process_exec");
    assert_eq!(execs.len(), 1, "one exec for the shell itself");
    let EventKind::ProcessExec { process } = &execs[0].kind else {
        panic!("wrong event kind");
    };
    assert_eq!(process.argv.first().map(String::as_str), Some("/bin/sh"));
    assert!(process.exe.is_some(), "the monitor reads the program path");
    assert!(process.cwd.is_some(), "the monitor reads the directory");
    assert_eq!(process.pid, execs[0].pid);

    let exits = handler.of_kind("process_exit");
    assert_eq!(exits.len(), 1);
    // The exit event carries the session identifier of the process at its
    // end; a process that never ran another program carries its detachment
    // nowhere else.
    assert!(matches!(
        exits[0].kind,
        EventKind::ProcessExit {
            code: Some(0),
            signal: None,
            sid: Some(_),
        }
    ));
}

#[test]
fn nested_session_links_every_child_to_the_root() {
    // The extra `true` keeps the shell from replacing itself with the next
    // program, so the tree really has three levels.
    let script = "/bin/sh -c '/bin/echo hi > /dev/null; true'; true";
    let (outcome, handler) = run_shell(script, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        handler.execs.len() >= 3,
        "expected at least three execs, got {}",
        handler.execs.len()
    );
    assert!(outcome.process_count >= 3);

    let root = handler.root_pid();
    for exec in &handler.execs {
        if exec.pid == root {
            continue;
        }
        let chain = handler
            .ancestry
            .get(&exec.pid)
            .unwrap_or_else(|| panic!("no ancestry for {}", exec.pid));
        assert_eq!(
            chain.last(),
            Some(&root),
            "process {} does not reach the root {root} through {chain:?}",
            exec.pid
        );
    }

    let echo = handler
        .execs
        .iter()
        .find(|info| info.program_name() == "echo")
        .expect("the deepest program is in the tree");
    let chain = &handler.ancestry[&echo.pid];
    assert_eq!(chain.len(), 2, "echo has a shell and the root above it");

    let forks = handler.of_kind("process_fork");
    assert!(!forks.is_empty(), "the monitor reports every new process");
}

#[test]
fn deny_stops_the_program_before_it_writes() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let allowed = dir.path().join("allowed");
    let marker = dir.path().join("denied-marker");
    let script = format!(
        "/bin/mkdir -p {}; /bin/touch {}; true",
        allowed.display(),
        marker.display()
    );

    let (outcome, handler) = run_shell(&script, Recorder::denying("touch"), 20);

    assert!(
        !marker.exists(),
        "the denied program must never run, but it made {}",
        marker.display()
    );
    assert!(
        allowed.exists(),
        "a program that no rule stops must still run"
    );
    assert_eq!(outcome.exit_code, Some(0), "the session itself continues");
    assert!(!outcome.terminated_by_firewall);

    let touch = handler
        .execs
        .iter()
        .find(|info| info.program_name() == "touch")
        .expect("the monitor saw the denied program");
    assert!(touch.argv.iter().any(|word| word.contains("denied-marker")));

    let killed = handler.of_kind("process_exit").into_iter().any(|event| {
        event.pid == touch.pid
            && matches!(
                event.kind,
                EventKind::ProcessExit {
                    signal: Some(9),
                    ..
                }
            )
    });
    assert!(killed, "the denied process ends through SIGKILL");
}

#[test]
fn terminate_session_stops_the_whole_tree() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("after-marker");
    // The sleep would keep the tree alive for a long time. The session must
    // end at once, so the test itself proves that the tree really dies.
    let script = format!("/bin/touch {}; /bin/sleep 30", marker.display());

    let (outcome, _handler) = run_shell(&script, Recorder::terminating("touch"), 20);

    assert!(outcome.terminated_by_firewall);
    assert_eq!(outcome.signal, Some(9));
    assert!(!marker.exists(), "the held program never ran");
}

#[test]
fn exit_code_is_reported() {
    let (outcome, _handler) = run_shell("exit 7", Recorder::default(), 20);
    assert_eq!(outcome.exit_code, Some(7));
    assert_eq!(outcome.signal, None);
    assert!(!outcome.is_success());
}

#[test]
fn ending_signal_is_reported() {
    let (outcome, handler) = run_shell("kill -TERM $$", Recorder::default(), 20);
    assert_eq!(outcome.exit_code, None);
    assert_eq!(outcome.signal, Some(15), "SIGTERM has the number 15");

    let exits = handler.of_kind("process_exit");
    assert!(exits.iter().any(|event| matches!(
        event.kind,
        EventKind::ProcessExit {
            code: None,
            signal: Some(15),
            ..
        }
    )));
}

#[test]
fn stdin_snapshot_reads_a_redirected_file() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let sql = dir.path().join("migrate.sql");
    std::fs::write(&sql, "DROP DATABASE customer_prod;\n").expect("write the script");
    let script = format!("/bin/cat < {} > /dev/null; true", sql.display());

    let (outcome, handler) = run_shell(&script, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    let snapshot = handler
        .inputs
        .get("cat")
        .expect("the monitor gives a snapshot for every exec");
    let stdin = snapshot
        .stdin
        .as_deref()
        .expect("descriptor 0 is a regular file, so the monitor reads it");
    assert!(
        stdin.contains("DROP DATABASE customer_prod;"),
        "the monitor read {stdin:?}"
    );

    let stdin_events = handler.of_kind("stdin_write");
    assert!(
        stdin_events.iter().any(|event| matches!(
            &event.kind,
            EventKind::StdinWrite { data, .. } if data.contains("DROP DATABASE")
        )),
        "the monitor makes a normalized event of the content"
    );

    // The redirect gives the file to the program, but the monitor opens its
    // own view of it. The program must still read every byte.
    let text = std::fs::read_to_string(&sql).expect("the file is still complete");
    assert_eq!(text, "DROP DATABASE customer_prod;\n");
}

#[test]
fn stdin_snapshot_skips_a_pipe() {
    // A pipe holds no stored content. A read would take the bytes away from
    // the program, so the monitor must report nothing.
    let (outcome, handler) = run_shell(
        "/bin/echo hi | /bin/cat > /dev/null",
        Recorder::default(),
        20,
    );
    assert_eq!(outcome.exit_code, Some(0));
    let snapshot = handler
        .inputs
        .get("cat")
        .expect("cat ran under the monitor");
    assert_eq!(snapshot.stdin, None);
}

#[test]
fn stdin_snapshot_reads_a_large_here_document() {
    // A shell keeps a small here-document in a pipe and a large one in a
    // deleted temporary file. The monitor can read the temporary file,
    // because a deleted file is still a regular file. The text stays below
    // the kernel limit of one argument, which is 128 KiB.
    let marker = "DROP DATABASE customer_prod;";
    let filler = "-".repeat(90_000);
    let script = format!("/bin/cat > /dev/null <<EOF\n{marker}\n{filler}\nEOF\n");

    let (outcome, handler) = run_shell(&script, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    let snapshot = handler
        .inputs
        .get("cat")
        .expect("cat ran under the monitor");
    match snapshot.stdin.as_deref() {
        Some(text) => {
            assert!(
                text.starts_with(marker),
                "the monitor read {:?}",
                &text[..40]
            );
            assert!(text.len() <= crate::DEFAULT_MAX_INPUT_BYTES);
        }
        None => panic!("a large here-document must use a file that the monitor can read"),
    }
}

#[test]
fn capture_input_can_be_switched_off() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let file = dir.path().join("secret.sql");
    std::fs::write(&file, "DROP DATABASE example;\n").expect("write the file");
    let mut config = MonitorConfig::new(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("/bin/cat < {} > /dev/null; true", file.display()),
    ]);
    config.capture_input = false;

    let (outcome, handler) = run_config(config, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        handler.inputs.is_empty(),
        "the monitor must read nothing when capture_input is false"
    );
    assert!(handler.of_kind("stdin_write").is_empty());
    assert!(handler
        .execs
        .iter()
        .any(|info| info.program_name() == "cat"));
}

#[test]
fn config_cwd_sets_the_working_directory() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let mut config = MonitorConfig::new(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "/bin/true".to_string(),
    ]);
    config.cwd = Some(dir.path().to_path_buf());

    let (outcome, handler) = run_config(config, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    let cwd = handler.execs[0].cwd.as_deref().expect("the directory");
    assert_eq!(
        std::fs::canonicalize(cwd).expect("real path"),
        std::fs::canonicalize(dir.path()).expect("real path")
    );
}

#[test]
fn read_process_reports_argv_exe_and_cwd() {
    let pid = std::process::id() as Pid;
    let info = Monitor::read_process(pid, &[]).expect("the test program is alive");

    assert_eq!(info.pid, pid);
    assert!(!info.argv.is_empty(), "the monitor reads the command line");
    let exe = info.exe.as_deref().expect("the monitor reads the path");
    assert!(Path::new(exe).is_absolute());
    let cwd = info
        .cwd
        .as_deref()
        .expect("the monitor reads the directory");
    assert_eq!(
        Path::new(cwd),
        std::env::current_dir().expect("current directory")
    );
    assert!(info.start_ticks > 0, "the key of a process needs the time");
    assert!(!info.comm.is_empty());
}

#[test]
fn read_process_returns_none_for_a_dead_process() {
    // Identifier 0 never names a normal process.
    assert!(Monitor::read_process(0, &[]).is_none());
    assert!(Monitor::read_process(-1, &[]).is_none());
}

#[test]
fn empty_command_is_an_error() {
    let _guard = lock();
    let config = MonitorConfig::default();
    let session = SessionMeta::new(Vec::new(), ".".to_string());
    let mut handler = Recorder::default();
    let error = Monitor::run(&config, &session, &mut handler).expect_err("no command");
    assert!(error.to_string().contains("empty"));
}

#[test]
fn missing_program_is_an_error() {
    let _guard = lock();
    let config = MonitorConfig::new(vec!["/nonexistent/agent-firewall-test".to_string()]);
    let session = SessionMeta::new(config.command.clone(), ".".to_string());
    let mut handler = Recorder::default();
    let error = Monitor::run(&config, &session, &mut handler).expect_err("no program");
    assert!(error.to_string().contains("cannot start"));
}

#[test]
fn capabilities_report_the_real_machine() {
    let _guard = lock();
    let caps = Monitor::capabilities(SyscallFilter::default());
    let by_name: HashMap<&str, &af_core::MonitorCapability> =
        caps.iter().map(|cap| (cap.name.as_str(), cap)).collect();

    for name in [
        "process_tree_tracking",
        "exec_interception",
        "argv_capture",
        "cwd_capture",
        "stdin_inspection",
        "syscall_filter",
        "file_open_events",
        "network_events",
        "unprivileged",
    ] {
        assert!(by_name.contains_key(name), "{name} is missing");
    }

    assert!(by_name["exec_interception"].available);
    assert!(by_name["process_tree_tracking"].available);
    assert!(by_name["argv_capture"].available);
    assert!(by_name["cwd_capture"].available);

    // The default mode installs the kernel filter, so this machine reports a
    // file and a network event. Both carry a remark that names their limit.
    assert!(by_name["file_open_events"].available);
    assert!(by_name["file_open_events"].detail.is_some());
    assert!(by_name["network_events"].available);
    assert!(by_name["network_events"].detail.is_some());
}

#[test]
fn script_snapshot_reads_an_interpreter_script() {
    let dir = tempfile::tempdir().expect("temporary directory");
    std::fs::write(
        dir.path().join("migrate.sh"),
        "psql -c 'DROP TABLE users'\n",
    )
    .expect("write the script");

    let info = ProcessInfo {
        pid: 1,
        exe: Some("/usr/bin/bash".to_string()),
        comm: "bash".to_string(),
        argv: vec!["bash".to_string(), "migrate.sh".to_string()],
        cwd: Some(dir.path().to_string_lossy().into_owned()),
        ..Default::default()
    };
    let text = inspect::script_snapshot(&info, 4096).expect("the script is readable");
    assert!(text.contains("DROP TABLE users"));
}

#[test]
fn script_snapshot_reads_a_database_script() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let file = dir.path().join("drop.sql");
    std::fs::write(&file, "DROP DATABASE example;\n").expect("write the script");

    let info = ProcessInfo {
        pid: 1,
        exe: Some("/usr/bin/psql".to_string()),
        comm: "psql".to_string(),
        argv: vec![
            "psql".to_string(),
            "-f".to_string(),
            file.to_string_lossy().into_owned(),
        ],
        ..Default::default()
    };
    let text = inspect::script_snapshot(&info, 4096).expect("the file is readable");
    assert!(text.contains("DROP DATABASE example;"));
}

#[test]
fn script_snapshot_skips_inline_code_and_other_programs() {
    let shell = ProcessInfo {
        exe: Some("/usr/bin/bash".to_string()),
        argv: vec!["bash".to_string(), "-c".to_string(), "rm -rf /".to_string()],
        ..Default::default()
    };
    // The code of `-c` is already in argv, so there is no file to read.
    assert_eq!(inspect::script_snapshot(&shell, 4096), None);

    let other = ProcessInfo {
        exe: Some("/usr/bin/git".to_string()),
        argv: vec!["git".to_string(), "push".to_string()],
        ..Default::default()
    };
    assert_eq!(inspect::script_snapshot(&other, 4096), None);
}

#[test]
fn script_snapshot_stops_at_the_byte_limit() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let file = dir.path().join("big.sql");
    std::fs::write(&file, "x".repeat(10_000)).expect("write the script");

    let info = ProcessInfo {
        exe: Some("/usr/bin/psql".to_string()),
        argv: vec!["psql".to_string(), format!("--file={}", file.display())],
        ..Default::default()
    };
    let text = inspect::script_snapshot(&info, 100).expect("the file is readable");
    assert_eq!(text.len(), 100);
}

#[test]
fn environment_keeps_only_useful_names() {
    let extra = vec!["PGPASSWORD".to_string()];

    assert_eq!(
        procfs::keep_env("PGDATABASE", "customer_prod", &extra),
        Some("customer_prod".to_string())
    );
    // HOME stays, because a rule compares a variable with the home directory
    // that the child shell expands it to.
    assert_eq!(
        procfs::keep_env("HOME", "/home/dev", &extra),
        Some("/home/dev".to_string())
    );
    // The name stays, because a rule can use its presence. The value goes.
    assert_eq!(
        procfs::keep_env("PGPASSWORD", "hunter2", &extra),
        Some(crate::REDACTED.to_string())
    );
    assert_eq!(
        procfs::keep_env("AWS_SECRET_ACCESS_KEY", "abc", &extra),
        None
    );
    assert_eq!(
        procfs::keep_env(
            "AWS_SECRET_ACCESS_KEY",
            "abc",
            &["AWS_SECRET_ACCESS_KEY".to_string()]
        ),
        Some(crate::REDACTED.to_string())
    );
}

#[test]
fn process_facts_of_the_monitor_itself_are_complete() {
    let pid = std::process::id() as Pid;
    let stat = procfs::read_stat(pid).expect("the test program is alive");
    assert!(stat.ppid > 0);
    assert!(stat.start_ticks > 0);
    assert!(!stat.comm.is_empty());
    assert_eq!(procfs::is_thread(pid), Some(false));
}

#[test]
fn a_program_with_threads_and_many_children_stays_complete() {
    let Some(python) = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        // The machine has no interpreter for this test. The other tests still
        // cover the tree, so this is not a failure.
        return;
    };
    let script = format!(
        "{python} -c 'import threading, subprocess\n\
         ts = [threading.Thread(target=lambda: subprocess.run([\"/bin/true\"])) for _ in range(8)]\n\
         [t.start() for t in ts]\n\
         [t.join() for t in ts]\n\
         '; for i in 1 2 3 4 5; do /bin/true; done"
    );

    let (outcome, handler) = run_shell(&script, Recorder::default(), 25);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        outcome.process_count >= 15,
        "the monitor must keep every task, got {}",
        outcome.process_count
    );

    let threads = handler
        .of_kind("process_fork")
        .into_iter()
        .filter(|event| {
            matches!(
                event.kind,
                EventKind::ProcessFork {
                    is_thread: true,
                    ..
                }
            )
        })
        .count();
    assert!(
        threads >= 8,
        "a clone that shares the address space is a thread, got {threads}"
    );

    let root = handler.root_pid();
    for exec in &handler.execs {
        if exec.pid == root {
            continue;
        }
        let chain = &handler.ancestry[&exec.pid];
        assert_eq!(
            chain.last(),
            Some(&root),
            "process {} lost the root",
            exec.pid
        );
    }
}

#[test]
fn target_scenario_finds_psql_with_its_full_provenance() {
    use std::os::unix::fs::PermissionsExt;

    // This is the scenario of the proof of concept:
    //   monitor -> sh -> migrate.sh -> psql -f drop.sql
    // The test copies a harmless program to the name `psql`, so no database
    // can change while the test runs.
    let dir = tempfile::tempdir().expect("temporary directory");
    let fake_psql = dir.path().join("psql");
    std::fs::copy("/bin/true", &fake_psql).expect("make a harmless psql");
    std::fs::set_permissions(&fake_psql, std::fs::Permissions::from_mode(0o755))
        .expect("make psql runnable");

    let sql = dir.path().join("drop.sql");
    std::fs::write(&sql, "DROP DATABASE example;\n").expect("write the statements");

    let script = dir.path().join("migrate.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n{} -f {}\ntrue\n",
            fake_psql.display(),
            sql.display()
        ),
    )
    .expect("write the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("make the script runnable");

    let (outcome, handler) = run_shell(
        &format!("{}; true", script.display()),
        Recorder::default(),
        20,
    );

    assert_eq!(outcome.exit_code, Some(0));

    let psql = handler
        .execs
        .iter()
        .find(|info| info.program_name() == "psql")
        .expect("the monitor saw the database client");
    assert!(psql.argv.iter().any(|word| word == "-f"));
    assert!(psql.cwd.is_some(), "the monitor knows the directory");
    assert_eq!(
        psql.exe.as_deref(),
        Some(fake_psql.to_string_lossy().as_ref())
    );

    // The chain goes back to the root through the script.
    let chain = &handler.ancestry[&psql.pid];
    assert_eq!(
        chain.len(),
        2,
        "psql, the script and the root make three levels"
    );
    assert_eq!(chain.last(), Some(&handler.root_pid()));

    // The dangerous statement is in the file of the `-f` option.
    let statements = handler.inputs["psql"]
        .script
        .as_deref()
        .expect("the monitor reads the file of the -f option");
    assert!(statements.contains("DROP DATABASE example;"));

    // The monitor also reads the shell script that started psql. The program
    // name comes from the real path, which is `bash` on many machines, so the
    // test looks at the content instead of at the name.
    let script_text = handler
        .inputs
        .values()
        .filter_map(|snapshot| snapshot.script.as_deref())
        .find(|text| text.starts_with("#!/bin/sh"))
        .expect("the monitor reads the script of an interpreter");
    assert!(script_text.contains("-f"));
}

// ---------------------------------------------------------------------------
// The kernel filter: what a running program does
// ---------------------------------------------------------------------------

/// Returns the shell that can open a connection, when the machine has one.
///
/// A connection needs a program that calls `connect`. `bash` can do it with
/// its `/dev/tcp` path and needs nothing installed. A machine without `bash`
/// cannot run these two tests, and the test says so instead of failing.
fn connect_shell() -> Option<&'static str> {
    ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|path| Path::new(path).exists())
}

/// Opens a port that nothing answers on, and keeps it open for the test.
fn listening_port() -> (std::net::TcpListener, u16) {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("a free port on the loopback address");
    let port = listener
        .local_addr()
        .expect("the address of the port")
        .port();
    (listener, port)
}

#[test]
fn a_write_open_is_observed_and_a_read_is_not() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let written = dir.path().join("written.txt");
    let read = dir.path().join("read-me.txt");
    std::fs::write(&read, "content\n").expect("write the file to read");

    let script = format!("/bin/cat {} > {}; true", read.display(), written.display());
    let (outcome, handler) =
        run_filtered(&script, SyscallFilter::WriteOnly, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        handler.opened("written.txt", true),
        "the write-intent open must reach the firewall, but it saw {:?}",
        handler.opens()
    );
    assert!(
        !handler
            .opens()
            .iter()
            .any(|(path, _)| path.contains("read-me.txt")),
        "the kernel drops a read-only open in this mode, but it reported {:?}",
        handler.opens()
    );

    // The action also becomes a recorded event, which is what the policy
    // engine and the trace both read.
    let events = handler.of_kind("file_open");
    assert!(
        events.iter().any(|event| matches!(
            &event.kind,
            EventKind::FileOpen { path, write: true } if path.contains("written.txt")
        )),
        "the monitor records the open as an event"
    );
}

#[test]
fn all_opens_mode_observes_a_read() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let read = dir.path().join("read-me.txt");
    std::fs::write(&read, "content\n").expect("write the file to read");

    let script = format!("/bin/cat {} > /dev/null; true", read.display());
    let (outcome, handler) =
        run_filtered(&script, SyscallFilter::AllOpens, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        handler.opened("read-me.txt", false),
        "every open reaches the firewall in this mode, but it saw {:?}",
        handler.opens()
    );
}

#[test]
fn the_filter_reaches_a_program_two_levels_deep() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let deep = dir.path().join("deep.txt");
    // The open happens in a shell inside a shell, and neither of them
    // installed a filter. Both got it from the root of the session.
    let script = format!(
        "/bin/sh -c '/bin/sh -c \"/bin/touch {}\"'; true",
        deep.display()
    );

    let (outcome, handler) =
        run_filtered(&script, SyscallFilter::WriteOnly, Recorder::default(), 20);

    assert_eq!(outcome.exit_code, Some(0));
    assert!(deep.exists(), "the program itself ran");
    assert!(
        handler.opened("deep.txt", true),
        "the filter is inherited by every child, but the firewall saw {:?}",
        handler.opens()
    );
}

#[test]
fn a_refused_open_fails_and_the_program_runs_on() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let refused = dir.path().join("secret.env");
    let after = dir.path().join("after.txt");
    // The first command is refused. The second one proves that the shell
    // itself survived the refusal and went on with its work.
    let script = format!(
        "/bin/touch {} 2>/dev/null; /bin/touch {}; true",
        refused.display(),
        after.display()
    );

    let (outcome, handler) = run_filtered(
        &script,
        SyscallFilter::WriteOnly,
        Recorder::refusing_path("secret.env"),
        20,
    );

    assert!(
        !refused.exists(),
        "the refused open must never make the file {}",
        refused.display()
    );
    assert!(
        after.exists(),
        "the program keeps running after a refusal, so the next command works"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the session itself is untouched"
    );
    assert!(!outcome.terminated_by_firewall);
    assert!(
        handler.opened("secret.env", true),
        "the firewall saw the open"
    );
}

#[test]
fn a_connection_is_observed_with_its_address_and_port() {
    let Some(shell) = connect_shell() else {
        eprintln!("no bash on this machine, so the connection test cannot run");
        return;
    };
    let (_listener, port) = listening_port();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && exec 3>&-");

    let config = MonitorConfig {
        syscall_filter: SyscallFilter::WriteOnly,
        ..MonitorConfig::new(vec![shell.to_string(), "-c".to_string(), script])
    };
    let (_outcome, handler) = run_config(config, Recorder::default(), 20);

    assert!(
        handler.connects().contains(&("127.0.0.1", port)),
        "the firewall must see the address and the port, but it saw {:?}",
        handler.connects()
    );
    let events = handler.of_kind("network_connect");
    assert!(
        events.iter().any(|event| matches!(
            &event.kind,
            EventKind::NetworkConnect { addr, port: seen, host: None }
                if addr == "127.0.0.1" && *seen == port
        )),
        "the monitor records the connection as an event, with no host name"
    );
}

#[test]
fn a_refused_connection_fails_in_the_program() {
    let Some(shell) = connect_shell() else {
        eprintln!("no bash on this machine, so the connection test cannot run");
        return;
    };
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("connected.txt");
    let (_listener, port) = listening_port();
    // The marker is only made when the connection worked.
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null && /bin/touch {}; true",
        marker.display()
    );

    let config = MonitorConfig {
        syscall_filter: SyscallFilter::WriteOnly,
        ..MonitorConfig::new(vec![shell.to_string(), "-c".to_string(), script])
    };
    let (outcome, handler) = run_config(config, Recorder::refusing_port(port), 20);

    assert!(
        !marker.exists(),
        "the refused connection must not reach the port"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the program handles the error itself"
    );
    assert!(handler.connects().contains(&("127.0.0.1", port)));
}

#[test]
fn the_off_mode_installs_no_filter_and_takes_no_privilege() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let status = dir.path().join("status.txt");
    let script = format!("/bin/cat /proc/self/status > {}", status.display());

    // The kernel floor needs the same promise as the filter, so a session
    // that keeps the floor also keeps `NoNewPrivs`. A session that switches
    // both off keeps the right to raise a privilege, exactly as before the
    // floor existed.
    let config = |landlock| MonitorConfig {
        syscall_filter: SyscallFilter::Off,
        landlock,
        landlock_home: Some(dir.path().to_path_buf()),
        ..MonitorConfig::new(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.clone(),
        ])
    };
    let (outcome, handler) = run_config(config(crate::LandlockMode::Off), Recorder::default(), 20);
    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        handler.actions.is_empty(),
        "a session with no filter observes no action, but it saw {:?}",
        handler.actions
    );

    let text = std::fs::read_to_string(&status).expect("the child wrote its own state");
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| panic!("the field {name} is in /proc/<pid>/status"))
    };
    assert_eq!(
        field("NoNewPrivs:"),
        "0",
        "a session with no filter and no floor keeps the right to raise a privilege"
    );
    assert_eq!(field("Seccomp:"), "0", "no filter is installed");

    let (outcome, _) = run_config(config(crate::LandlockMode::On), Recorder::default(), 20);
    assert_eq!(outcome.exit_code, Some(0));
    let text = std::fs::read_to_string(&status).expect("the child wrote its own state");
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| panic!("the field {name} is in /proc/<pid>/status"))
    };
    assert_eq!(
        field("NoNewPrivs:"),
        "1",
        "the kernel floor needs the no-new-privileges promise, whatever the filter mode"
    );
    assert_eq!(field("Seccomp:"), "0", "no filter is installed");
}

/// The kernel floor denies a credential read two shells deep and explains it.
///
/// The path is an invented key name under the real `.ssh` of the user: the
/// floor hides the whole directory, so the denial happens whether or not the
/// file exists, and no real credential is ever read. The test needs a real
/// home directory because the carve-out is what hides the store — a home
/// under `/tmp` or under the work tree would be writable there, which is
/// exactly the soundness rule the last test of this group proves.
#[test]
fn the_floor_denies_a_credential_read_two_shells_deep_and_explains_it() {
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("no HOME on this machine, so the floor test cannot run");
        return;
    };
    let key = Path::new(&home).join(".ssh").join("id_afw_floor_test");

    let script = format!("sh -c 'cat {}'", key.display());
    let config = MonitorConfig {
        syscall_filter: SyscallFilter::AllOpens,
        landlock: crate::LandlockMode::On,
        ..MonitorConfig::new(vec!["/bin/sh".to_string(), "-c".to_string(), script])
    };
    let (outcome, handler) = run_config(config, Recorder::default(), 20);

    // The read failed, and the session said why.
    assert_ne!(outcome.exit_code, Some(0), "the credential read must fail");
    let denials = handler.of_kind("kernel_denied");
    assert_eq!(
        denials.len(),
        1,
        "one kernel denial is reported:\n{:?}",
        handler.events
    );
    let EventKind::KernelDenied { rule, path } = &denials[0].kind else {
        panic!("wrong event kind");
    };
    assert_eq!(rule.as_deref(), Some("filesystem.credentials.read"));
    assert_eq!(path, &key.display().to_string());

    // The floor became a fact of the session before the first program ran.
    assert_eq!(
        handler.of_kind("kernel_floor").len(),
        1,
        "the session records its kernel floor"
    );
}

/// The same session without the floor reads the path without a kernel
/// denial, so the refusal is the floor and nothing else.
#[test]
fn a_session_without_the_floor_reports_no_kernel_denial() {
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("no HOME on this machine, so the floor test cannot run");
        return;
    };
    let target = Path::new(&home).join(".ssh").join("id_afw_floor_test");

    let script = format!("cat {}", target.display());
    let config = MonitorConfig {
        syscall_filter: SyscallFilter::AllOpens,
        landlock: crate::LandlockMode::Off,
        ..MonitorConfig::new(vec!["/bin/sh".to_string(), "-c".to_string(), script])
    };
    let (outcome, handler) = run_config(config, Recorder::default(), 20);
    assert_eq!(
        outcome.exit_code,
        Some(1),
        "the invented key does not exist, so the read fails with an ordinary error"
    );
    assert!(
        handler.of_kind("kernel_denied").is_empty(),
        "no kernel denial is reported without the floor"
    );
}

/// The floor hides the credential stores of the home directory and nothing
/// else: a `.ssh` inside the work tree stays writable, because a sandbox that
/// stopped the work would stop the work.
#[test]
fn the_floor_leaves_a_ssh_directory_of_the_work_tree_alone() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("make the home directory");
    std::fs::create_dir_all(dir.path().join(".ssh")).expect("make a project ssh directory");
    let target = dir.path().join(".ssh").join("known_hosts");

    let script = format!("echo host > {}", target.display());
    let config = MonitorConfig {
        landlock: crate::LandlockMode::On,
        landlock_home: Some(home),
        cwd: Some(dir.path().to_path_buf()),
        ..MonitorConfig::new(vec!["/bin/sh".to_string(), "-c".to_string(), script])
    };
    let (outcome, _) = run_config(config, Recorder::default(), 20);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the write inside the work tree works"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("the file was written"),
        "host\n"
    );
}

#[test]
fn the_write_only_mode_installs_the_filter_in_the_child() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let status = dir.path().join("status.txt");
    let script = format!("/bin/cat /proc/self/status > {}", status.display());

    let (outcome, _handler) =
        run_filtered(&script, SyscallFilter::WriteOnly, Recorder::default(), 20);
    assert_eq!(outcome.exit_code, Some(0));

    let text = std::fs::read_to_string(&status).expect("the child wrote its own state");
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    };
    // `Seccomp: 2` is the filter mode. The value proves that the filter of the
    // root reached a program two processes later, with no install of its own.
    assert_eq!(field("Seccomp:"), "2", "the filter is inherited");
    assert_eq!(
        field("NoNewPrivs:"),
        "1",
        "an unprivileged filter needs this promise"
    );
}

#[test]
fn a_program_that_raises_privilege_gets_an_explanation() {
    // The test needs no real `sudo` and no privilege. The monitor reads the
    // name of the program from its own path, so a copy of `true` under the
    // name `sudo` reaches exactly the same code. It must be a real program
    // and not a script, because a script runs under the name of its
    // interpreter.
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temporary directory");
    let fake = dir.path().join("sudo");
    let source = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .expect("a program to copy");
    std::fs::copy(source, &fake).expect("copy the program");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
        .expect("make the program runnable");

    let (_outcome, handler) = run_shell(
        &format!("{} ; true", fake.display()),
        Recorder::default(),
        20,
    );

    let warned = handler.of_kind("monitor_warning").into_iter().any(|event| {
        matches!(&event.kind, EventKind::MonitorWarning { message }
            if message.contains("sudo") && message.contains("setuid"))
    });
    assert!(
        warned,
        "the monitor explains why sudo cannot work, instead of leaving the user to guess"
    );
}

#[test]
fn the_capability_report_follows_the_filter_mode() {
    // The probe of the capability report starts a traced child of its own,
    // and a tracer of a session that runs at the same time would reap its
    // exit. The lock keeps the two apart.
    let _guard = lock();
    let detail_of = |caps: &[af_core::MonitorCapability], name: &str| {
        caps.iter()
            .find(|cap| cap.name == name)
            .map(|cap| (cap.available, cap.detail.clone().unwrap_or_default()))
            .unwrap_or_else(|| panic!("the report holds {name}"))
    };

    let off = Monitor::capabilities(SyscallFilter::Off);
    assert!(!detail_of(&off, "file_open_events").0);
    assert!(!detail_of(&off, "network_events").0);

    let write_only = Monitor::capabilities(SyscallFilter::WriteOnly);
    assert!(detail_of(&write_only, "file_open_events").0);
    assert!(detail_of(&write_only, "network_events").0);
    assert!(
        detail_of(&write_only, "file_open_events")
            .1
            .contains("read"),
        "the report must name the read that this mode does not see"
    );

    let all_opens = Monitor::capabilities(SyscallFilter::AllOpens);
    assert!(detail_of(&all_opens, "file_open_events").0);
    assert!(detail_of(&all_opens, "syscall_filter")
        .1
        .contains("all-opens"));
}

/// Writes a file that begins with the sixteen bytes of an ELF header.
fn write_elf_header(path: &Path, class: u8) {
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = class;
    // Little endian, current version, System V.
    header[5] = 1;
    header[6] = 1;
    std::fs::write(path, header).expect("write the header");
}

/// Writes a minimal 64-bit ELF file with one program header entry of the
/// given type.
fn write_elf_with_phdr(path: &Path, entry_type: u32) {
    let phoff: u64 = 64;
    let phentsize: u16 = 56;
    let phnum: u16 = 1;
    let mut bytes = vec![0u8; 64 + phentsize as usize];
    bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // little endian
    bytes[6] = 1; // current version
    bytes[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&phentsize.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&phnum.to_le_bytes());
    bytes[64..68].copy_from_slice(&entry_type.to_le_bytes());
    std::fs::write(path, bytes).expect("write the program");
}

/// The monitor must know a program that needs the dynamic linker from one
/// that does not.
///
/// Correlation keys on this fact: a dynamic child of a session that carries
/// the sensor preload must load it, and a static child never can. The
/// presence of `PT_INTERP` in the program header table is the whole answer,
/// and a file that is not a readable ELF program gives `None`, because the
/// monitor never guesses.
#[test]
fn the_monitor_reads_whether_a_program_needs_the_linker() {
    let dir = tempfile::tempdir().expect("temporary directory");

    let dynamic = dir.path().join("dynamic");
    write_elf_with_phdr(&dynamic, 3 /* PT_INTERP */);
    assert_eq!(procfs::is_dynamic_elf(&dynamic), Some(true));

    let statik = dir.path().join("static");
    write_elf_with_phdr(&statik, 1 /* PT_LOAD */);
    assert_eq!(procfs::is_dynamic_elf(&statik), Some(false));

    let script = dir.path().join("script.sh");
    std::fs::write(&script, "#!/bin/sh\ntrue\n").expect("write the script");
    assert_eq!(procfs::is_dynamic_elf(&script), None);
    assert_eq!(
        procfs::is_dynamic_elf(&dir.path().join("nothing-here")),
        None
    );

    // The program of this test itself is dynamic, and a static helper of the
    // repository proves the other side on a real file.
    let own = std::env::current_exe().expect("the path of this test");
    assert_eq!(procfs::is_dynamic_elf(&own), Some(true));
}

/// The monitor must know a 32-bit program from a 64-bit one.
///
/// The kernel filter holds the call numbers of one architecture. A 32-bit
/// program on a 64-bit machine uses another table, so the filter lets it
/// through and the monitor has to say so. The fifth byte of the file is the
/// whole answer: 1 is 32-bit and 2 is 64-bit.
#[test]
fn the_monitor_reads_the_class_of_a_program() {
    let dir = tempfile::tempdir().expect("temporary directory");

    let elf32 = dir.path().join("thirty-two");
    write_elf_header(&elf32, 1);
    assert!(procfs::is_elf32(&elf32), "a class of 1 is a 32-bit program");

    let elf64 = dir.path().join("sixty-four");
    write_elf_header(&elf64, 2);
    assert!(
        !procfs::is_elf32(&elf64),
        "a class of 2 is a 64-bit program"
    );

    // A file that is no ELF program at all, and a file that is not there,
    // both give `false`. The monitor never guesses.
    let script = dir.path().join("script.sh");
    std::fs::write(&script, "#!/bin/sh\ntrue\n").expect("write the script");
    assert!(!procfs::is_elf32(&script));
    let short = dir.path().join("short");
    std::fs::write(&short, [0x7f, b'E']).expect("write the short file");
    assert!(!procfs::is_elf32(&short));
    assert!(!procfs::is_elf32(&dir.path().join("nothing-here")));

    // The program of this test is a 64-bit program on this machine, and the
    // real path must give the same answer as the crafted header.
    let own = std::env::current_exe().expect("the path of this test");
    assert_eq!(procfs::is_elf32(&own), cfg!(target_pointer_width = "32"));
}
