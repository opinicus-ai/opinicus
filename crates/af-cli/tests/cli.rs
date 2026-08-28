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
