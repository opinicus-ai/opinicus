//! The redacted bundle of one session, for a false-positive report.
//!
//! A user whose normal work was questioned, refused or stopped can attach
//! evidence to the false-positive issue template — but a trace is private
//! data: command lines, paths, environment values. This module turns a
//! recorded trace into a **report** the user can post: the whole event
//! stream, redacted with the same machinery as the telemetry samples
//! ([`crate::redaction`]), so the maintainers can see the exact shape the
//! rules judged without seeing the machine.
//!
//! What a report keeps and what it never carries:
//!
//! * **Redacted everywhere**: assignments whose name marks a secret
//!   (`password=…` → `password=<redacted>`), and credentials with a
//!   well-known prefix (`ghp_…`, `sk-…`, `AKIA…`) are swallowed whole.
//! * **Never carried**: the values of environment maps (the names stay, the
//!   values become `<redacted>`), the content of observed input and read
//!   files (the `data` fields become `<omitted>`; content stays local), and
//!   the `value` of an environment change.
//! * **Pseudonymized**: the session identifier, process identifiers, the
//!   home directory, login names under `/home` and `/Users`, and the host
//!   name — the same [`Pseudonyms`] the samples use, so two reports of one
//!   machine can be compared and nobody can read the machine back out of
//!   them.
//!
//! The report is a local file until the user attaches it. Nothing here
//! sends anything; no network code exists in this workspace.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use af_core::{Decision, Event, EventKind};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::redaction::{redact_text, Pseudonyms, REDACTED};

/// The schema marker of a report file.
pub const REPORT_SCHEMA: &str = "af-false-positive-report/1";

/// Text that replaces content that never travels: observed input and the
/// body of read files.
const OMITTED: &str = "<omitted: content stays local>";

/// Keys whose value is a path: the login prefix is pseudonymized on top of
/// the secret redaction.
const PATH_KEYS: &[&str] = &["cwd", "exe", "path", "from", "to", "preload"];

/// Keys whose number is a process identifier: the identifier is
/// pseudonymized, so the chain stays readable and the machine stays
/// unnamed.
const PID_KEYS: &[&str] = &[
    "pid",
    "ppid",
    "sid",
    "root_sid",
    "child_pid",
    "target",
    "monitor_pid",
    "root_pid",
];

/// The redacted bundle of one session.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FalsePositiveReport {
    /// The schema marker: [`REPORT_SCHEMA`].
    pub schema: String,
    /// The pseudonymized session reference: `s-…`.
    pub session: String,
    /// How many events the trace held.
    pub events: usize,
    /// Every rule identifier the session named, sorted, without repeats.
    pub rules: Vec<String>,
    /// The redacted events of the trace, in order.
    pub trace: Vec<Value>,
    /// What the report did to the trace, so nobody has to guess.
    pub redaction: Vec<&'static str>,
}

impl FalsePositiveReport {
    /// Returns the file name a report of one session takes by default:
    /// `agent-firewall-report-<session reference>.json`.
    pub fn default_file_name(&self) -> String {
        format!("agent-firewall-report-{}.json", self.session)
    }
}

/// Builds the redacted report of one recorded session.
///
/// The function reads only the events it is given and writes nothing; the
/// caller writes the file with [`write_report`]. The rules list carries
/// every rule identifier the session named, so an issue can name them even
/// before anyone opens the trace.
pub fn build_report(events: &[Event]) -> FalsePositiveReport {
    let start_ts = events.first().map(|event| event.ts).unwrap_or(0);
    let mut scrubber = Scrubber {
        pseu: Pseudonyms::from_environment(),
        start_ts,
    };
    let session = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::SessionStart { meta, .. } => Some(meta.session_id.to_string()),
            _ => None,
        })
        .or_else(|| events.first().map(|event| event.session_id.to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let session = scrubber.pseu.session(&session);

    let mut rules = std::collections::BTreeSet::new();
    for event in events {
        match &event.kind {
            EventKind::PolicyDecision { verdict, .. } => {
                if verdict.decision != Decision::Allow {
                    for matched in &verdict.matches {
                        rules.insert(matched.rule_id.clone());
                    }
                }
            }
            EventKind::ApprovalRequested { rule_id, .. }
            | EventKind::ApprovalResolved { rule_id, .. } => {
                rules.insert(rule_id.clone());
            }
            EventKind::QuarantineStarted { rule, .. }
            | EventKind::QuarantineResolved { rule, .. } => {
                rules.insert(rule.clone());
            }
            EventKind::KernelDenied {
                rule: Some(rule), ..
            } => {
                rules.insert(rule.clone());
            }
            _ => {}
        }
    }

    let trace = events
        .iter()
        .map(|event| scrubber.event_value(event))
        .collect();

    FalsePositiveReport {
        schema: REPORT_SCHEMA.to_string(),
        session,
        events: events.len(),
        rules: rules.into_iter().collect(),
        trace,
        redaction: vec![
            "secret assignments and known-prefix credentials are <redacted>",
            "environment values never travel; names stay",
            "observed content and read files are <omitted>",
            "session, process, home, login and host identifiers are pseudonymized",
        ],
    }
}

/// Writes a report to a file.
///
/// The file is pretty JSON, so a text editor is a complete inspector, and
/// it is created with the permission mode `0600`, like every file this
/// workspace writes for the user: even redacted, a report names sessions
/// and paths, and it is the user's choice whom to show it to.
pub fn write_report(path: &Path, report: &FalsePositiveReport) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())
}

/// Scrubs one event into its report form.
struct Scrubber {
    pseu: Pseudonyms,
    /// Time of the first event, for the relative time stamps.
    start_ts: u64,
}

impl Scrubber {
    /// Packs one event: its time, its process reference and its scrubbed
    /// body. The order follows the trace, so the report reads like the
    /// session.
    fn event_value(&mut self, event: &Event) -> Value {
        let mut object = Map::new();
        object.insert(
            "at_ms".into(),
            json!(event.ts.saturating_sub(self.start_ts) / 1_000_000),
        );
        object.insert("process".into(), json!(self.pseu.pid(event.pid)));
        if let Some(tag) = &event.agent {
            object.insert("agent".into(), json!(tag.name));
        }
        let body = serde_json::to_value(&event.kind).unwrap_or(Value::Null);
        if let Some(body) = body.as_object() {
            for (key, value) in body {
                object.insert(key.clone(), self.value(key, value));
            }
        }
        Value::Object(object)
    }

    /// Scrubs one value of the trace body.
    fn value(&mut self, key: &str, value: &Value) -> Value {
        match value {
            // An environment map: the names are the payload, the values
            // never travel — whatever they look like.
            Value::Object(map) if key == "env" => {
                let redacted: Map<String, Value> = map
                    .keys()
                    .map(|name| (name.clone(), Value::String(REDACTED.to_string())))
                    .collect();
                Value::Object(redacted)
            }
            Value::Object(map) => {
                let out: Map<String, Value> = map
                    .iter()
                    .map(|(name, value)| (name.clone(), self.value(name, value)))
                    .collect();
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| self.value(key, item))
                    .collect::<Vec<_>>(),
            ),
            Value::String(text) => Value::String(self.text(key, text)),
            Value::Number(number) => {
                // Zero means the fact is absent (a session that named no
                // monitor, a process with no parent), so it stays a zero and
                // consumes no reference.
                if PID_KEYS.contains(&key) {
                    if let Some(pid) = number.as_i64() {
                        if pid != 0 {
                            return Value::String(self.pseu.pid(pid as af_core::Pid));
                        }
                    }
                }
                Value::Number(number.clone())
            }
            other => other.clone(),
        }
    }

    /// Scrubs one string of the trace body.
    fn text(&mut self, key: &str, text: &str) -> String {
        // Content stays local, in every shape the schema carries it.
        if key == "data" || key == "value" {
            return OMITTED.to_string();
        }
        if key == "session_id" {
            return self.pseu.session(text);
        }
        if PATH_KEYS.contains(&key) {
            return self.pseu.path(&redact_text(text));
        }
        self.pseu.scrub(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::{
        Action, ApprovalOutcome, ProcessInfo, RiskLevel, RuleMatch, SessionId, SessionMeta, Verdict,
    };

    /// Builds a small trace with a secret in argv and in the environment,
    /// the shape the CLI fixture test drives end to end.
    fn trace_with_secrets() -> Vec<Event> {
        let mut session = SessionMeta::new(
            vec!["bash".to_string(), "migrate.sh".to_string()],
            "/home/dev/project".to_string(),
        );
        session.session_id = SessionId::from("afw-report-test");
        let secret_argv = "--api-key=sk-ant-api03-ZZZsecretZZZ123456";
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "ANTHROPIC_API_KEY".to_string(),
            "sk-ant-api03-ZZZsecretZZZ123456".to_string(),
        );
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let mut process = ProcessInfo {
            pid: 401,
            ppid: Some(400),
            comm: "psql".to_string(),
            argv: vec!["psql".to_string(), secret_argv.to_string()],
            env: env.clone(),
            ..ProcessInfo::default()
        };
        process.cwd = Some("/home/dev/project".to_string());
        let action = Action::Exec {
            exe: Some("/usr/bin/psql".to_string()),
            program: "psql".to_string(),
            argv: process.argv.clone(),
            cwd: process.cwd.clone(),
            env: env.clone(),
        };
        let verdict = Verdict::from_matches(vec![RuleMatch {
            rule_id: "database.destructive.drop-database".to_string(),
            title: "Drop a database".to_string(),
            category: "database".to_string(),
            risk: RiskLevel::ApprovalRequired,
            decision: Decision::ApprovalRequired,
            quarantine: false,
            reason: "the statement removes a whole database".to_string(),
        }]);
        let session_id = session.session_id.clone();
        vec![
            Event::new(
                session_id.clone(),
                400,
                EventKind::SessionStart {
                    meta: Box::new(session),
                    capabilities: Vec::new(),
                },
            ),
            Event::new(
                session_id.clone(),
                401,
                EventKind::ProcessExec {
                    process: Box::new(process),
                },
            ),
            Event::new(
                session_id.clone(),
                401,
                EventKind::PolicyDecision {
                    action: Box::new(action),
                    verdict: Box::new(verdict),
                    ancestry: Vec::new(),
                },
            ),
            Event::new(
                session_id.clone(),
                401,
                EventKind::ApprovalResolved {
                    rule_id: "database.destructive.drop-database".to_string(),
                    outcome: ApprovalOutcome::Deny,
                    waited_ms: 1,
                },
            ),
            Event::new(
                session_id,
                401,
                EventKind::StdinWrite {
                    stream: af_core::InputStream::Stdin,
                    data: "password=TOPSECRETPASSWORD inside content".to_string(),
                },
            ),
        ]
    }

    #[test]
    fn a_report_carries_no_secret_from_argv_or_env() {
        let report = build_report(&trace_with_secrets());
        let text = serde_json::to_string(&report).expect("serialize");
        assert!(!text.contains("ZZZsecretZZZ"), "{text}");
        assert!(!text.contains("TOPSECRETPASSWORD"), "{text}");
        // The shapes survive: the assignment keeps its name, the prefix
        // credential is swallowed whole, the environment keeps its names.
        assert!(text.contains("--api-key=<redacted>"), "{text}");
        assert!(
            text.contains("\"ANTHROPIC_API_KEY\":\"<redacted>\""),
            "{text}"
        );
        assert!(text.contains("\"PATH\":\"<redacted>\""), "{text}");
    }

    #[test]
    fn observed_content_is_omitted_not_redacted() {
        let report = build_report(&trace_with_secrets());
        let text = serde_json::to_string(&report).expect("serialize");
        assert!(text.contains("<omitted: content stays local>"), "{text}");
    }

    #[test]
    fn the_report_names_every_rule_the_session_named() {
        let report = build_report(&trace_with_secrets());
        assert_eq!(report.rules, vec!["database.destructive.drop-database"]);
        assert_eq!(report.events, 5);
    }

    #[test]
    fn the_report_pseudonymizes_the_session_and_the_processes() {
        let report = build_report(&trace_with_secrets());
        let text = serde_json::to_string(&report).expect("serialize");
        assert!(!text.contains("afw-report-test"), "{text}");
        assert!(report.session.starts_with("s-"), "{}", report.session);
        assert!(text.contains("\"process\":\"p1\""), "{text}");
        assert!(text.contains("\"process\":\"p2\""), "{text}");
    }

    #[test]
    fn the_report_file_is_written_for_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("report.json");
        let report = build_report(&trace_with_secrets());
        write_report(&path, &report).expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(&path).expect("read"),
        )
        .expect("parse");
        assert_eq!(back["schema"], json!(report.schema));
        assert_eq!(back["rules"], json!(report.rules));
        assert_eq!(back["events"], json!(report.events));
        assert_eq!(
            report.default_file_name(),
            format!("agent-firewall-report-{}.json", report.session)
        );
    }
}
