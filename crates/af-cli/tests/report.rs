//! End-to-end tests of the `report` sub-command.
//!
//! The command is the false-positive report path of [af-13]: it validates a
//! trace, redacts it and writes a local bundle the user can attach to the
//! issue template. These tests drive the built binary against a static
//! fixture trace that carries secrets in argv and in the environment — the
//! one shape the command exists to make safe. No live session is needed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture trace: a denied `psql` with a secret in argv and env.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("false-positive-trace.jsonl")
}

/// The secret that the fixture carries in argv and environment.
const SECRET: &str = "ZZZsecretZZZ";

/// The second secret, the assignment shape inside observed content.
const CONTENT_SECRET: &str = "TOPSECRETPASSWORD";

/// Runs the built binary with these arguments.
fn firewall(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-firewall"))
        .args(args)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn a_report_of_a_trace_with_secrets_carries_no_secret() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let out = dir.path().join("report.json");
    let (code, stdout, stderr) = firewall(&[
        "report",
        fixture().to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "{stdout}{stderr}");
    let text = std::fs::read_to_string(&out).expect("the report exists");
    assert!(
        !text.contains(SECRET),
        "the argv/env secret must not survive into the report:\n{text}"
    );
    assert!(
        !text.contains(CONTENT_SECRET),
        "a secret inside observed content must not survive:\n{text}"
    );
    // The evidence survives in redacted shape: the rule, the command line
    // with the secret gone, the environment names with dead values.
    assert!(
        text.contains("database.destructive.drop-database"),
        "{text}"
    );
    assert!(text.contains("--api-key=<redacted>"), "{text}");
    assert!(
        text.contains("\"ANTHROPIC_API_KEY\": \"<redacted>\""),
        "{text}"
    );
    assert!(text.contains("<omitted: content stays local>"), "{text}");
    // The user knows what to do with the file, and that nothing was sent.
    assert!(
        stdout.contains("attach it to the false-positive template"),
        "{stdout}"
    );
    assert!(stdout.contains("nothing is sent anywhere"), "{stdout}");
}

#[test]
fn the_report_file_is_private_to_its_owner() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let out = dir.path().join("report.json");
    let (code, stdout, stderr) = firewall(&[
        "report",
        fixture().to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let mode = std::fs::metadata(&out).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the user decides whom to show the report");
}

#[test]
fn a_broken_trace_is_refused_and_not_reported() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let broken = dir.path().join("broken.jsonl");
    std::fs::write(&broken, b"{\"seq\":1,\"not\":\"an event\"}\n").expect("write");
    let out = dir.path().join("never.json");
    let (code, _stdout, stderr) = firewall(&[
        "report",
        broken.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "a damaged trace must not become a report");
    assert!(stderr.contains("holds no valid trace"), "{stderr}");
    assert!(!out.exists(), "no report was written");
}

#[test]
fn an_empty_trace_is_refused() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let empty = dir.path().join("empty.jsonl");
    std::fs::write(&empty, b"\n").expect("write");
    let (code, _stdout, stderr) = firewall(&["report", empty.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("holds no event"), "{stderr}");
}

#[test]
fn the_default_output_lands_in_the_working_directory() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_agent-firewall"))
        .args(["report", fixture().to_str().unwrap()])
        .current_dir(dir.path())
        .output()
        .expect("the binary runs");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("report: "), "{stdout}");
    let made: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read the directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("agent-firewall-report-")
        })
        .collect();
    assert_eq!(made.len(), 1, "one report file, named after the session");
}
