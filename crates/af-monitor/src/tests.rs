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

use af_core::{Event, EventKind, Pid, ProcessInfo, SessionMeta};

use crate::{
    inspect, procfs, InputSnapshot, Intercept, Monitor, MonitorConfig, MonitorHandler,
    SessionOutcome,
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

    /// Returns the identifier of the process of the first exec event.
    fn root_pid(&self) -> Pid {
        self.execs.first().expect("at least one exec").pid
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
    assert!(matches!(
        exits[0].kind,
        EventKind::ProcessExit {
            code: Some(0),
            signal: None
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
            signal: Some(15)
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
    let caps = Monitor::capabilities();
    let by_name: HashMap<&str, &af_core::MonitorCapability> =
        caps.iter().map(|cap| (cap.name.as_str(), cap)).collect();

    for name in [
        "process_tree_tracking",
        "exec_interception",
        "argv_capture",
        "cwd_capture",
        "stdin_inspection",
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

    assert!(!by_name["file_open_events"].available);
    assert!(by_name["file_open_events"].detail.is_some());
    assert!(!by_name["network_events"].available);
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
    assert_eq!(procfs::keep_env("HOME", "/home/dev", &extra), None);
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
