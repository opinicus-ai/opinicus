//! Sample selection, redaction and the local outbox.
//!
//! A sample is the payload of [DIRECTION.md §7]: the process tree, the
//! command lines, the observed content, the file and network actions, the
//! environment names, the policy decisions and the agent identity, around
//! one **trigger** — an event that made the firewall ask, quarantine, refuse
//! or sense an attack on its own visibility. A fixed window of surrounding
//! events gives the researcher the behavioral context, and every field
//! passes the redaction and pseudonymization of [`crate::redaction`]
//! according to the granted [`Scope`]s.
//!
//! A sample never leaves the machine on its own. It is written to a local
//! outbox directory as plain JSON, one file per sample, where the user can
//! read it and delete it. No code anywhere sends it.
//!
//! [DIRECTION.md §7]: https://github.com/agent-firewall/agent-firewall/blob/main/docs/DIRECTION.md

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use af_core::{Action, AgentTag, Decision, Event, EventKind, ProcessInfo, SessionMeta, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::redaction::{cap, redact_text, Pseudonyms, REDACTED};
use crate::sha256;
use crate::{Consent, Scope};

/// The schema marker of a sample file.
pub const SAMPLE_SCHEMA: &str = "af-telemetry-sample/1";

/// How many events before and after a trigger the sample carries.
pub const DEFAULT_WINDOW: usize = 20;

/// How many characters of observed content a sample may carry, after
/// redaction.
pub const MAX_CONTENT_CHARS: usize = 2000;

/// The largest program file that a sample hashes. A bigger file is named by
/// path and hash-less.
pub const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// The packaging options of one run.
#[derive(Debug, Clone)]
pub struct Options {
    /// The event window around one trigger.
    pub window: usize,
    /// The home directory to pseudonymize, when it is known.
    pub home: Option<String>,
    /// The host name to pseudonymize, when it is known.
    pub host: Option<String>,
}

impl Options {
    /// Reads the home directory and the host name of this machine, the same
    /// way [`Pseudonyms::from_environment`] does.
    pub fn from_environment() -> Self {
        let home = std::env::var("HOME").ok().filter(|value| !value.is_empty());
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self {
            window: DEFAULT_WINDOW,
            home,
            host,
        }
    }
}

/// One reason a sample exists: the trigger event, the rule when one matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleReason {
    /// The event kind that triggered the sample.
    pub kind: String,
    /// The rule that matched, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// When the trigger happened, in milliseconds after the session start.
    pub at_ms: u64,
}

/// One process of the sample tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    /// The pseudonymized reference of the process: `p1`, `p2`, …
    pub reference: String,
    /// The reference of the parent, when the trace names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The program name, for example `psql`. Absent when the trace never saw
    /// the process run a program — a denied child, or the monitor itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comm: String,
    /// The executable path, pseudonymized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The SHA-256 of the executable file, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_hash: Option<String>,
}

/// The agent identity of the session, as the detectors assessed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Name of the identified agent.
    pub name: String,
    /// Combined confidence of the detection.
    pub confidence: f32,
    /// Every signal the detectors found, with scrubbed detail lines.
    pub signals: Vec<SignalLine>,
}

/// One detection signal of the sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalLine {
    /// Name of the detector that found the marker.
    pub detector: String,
    /// Agent the marker names.
    pub agent: String,
    /// What the detector saw, scrubbed.
    pub detail: String,
    /// Weight of the finding.
    pub confidence: f32,
}

/// One redacted, pseudonymized extract around a trigger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// The schema marker: [`SAMPLE_SCHEMA`].
    pub schema: String,
    /// The pseudonymized session reference: `s-…`.
    pub session: String,
    /// The scopes that were granted when the sample was packaged.
    pub consent: Vec<String>,
    /// The agent identity, when the `identity` scope is granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentIdentity>,
    /// Why the sample exists: every trigger in the window.
    pub reasons: Vec<SampleReason>,
    /// The process tree of the window, when the `tree` scope is granted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<ProcessNode>,
    /// The redacted events of the window, in order.
    pub events: Vec<Value>,
}

impl Sample {
    /// Returns the triggers of the sample that carry a rule.
    pub fn rules(&self) -> Vec<&str> {
        self.reasons
            .iter()
            .filter_map(|reason| reason.rule.as_deref())
            .collect()
    }
}

/// Builds the samples of one recorded session.
///
/// The function reads only the events it is given; it opens program files
/// for hashing and nothing else, and it writes nothing. With no trigger in
/// the trace it returns no sample. The scopes of the consent decide what
/// each sample carries; a consent with no scope still packages the bare
/// reasons, because the caller already checked that the user granted
/// something.
pub fn build_samples(events: &[Event], consent: &Consent, options: &Options) -> Vec<Sample> {
    if events.is_empty() {
        return Vec::new();
    }
    let session = session_of(events);
    let start_ts = events[0].ts;
    let mut packer = Packer {
        consent,
        pseu: Pseudonyms::new(options.home.as_deref(), options.host.as_deref()),
        start_ts,
    };
    let session_ref = packer.pseu.session(session.session_id.as_str());
    // Reference every process of the whole trace first, in event order, so
    // the same process keeps the same reference in every sample of the run.
    for event in events {
        pre_scan(event, &mut packer.pseu);
    }
    let tree_map = tree_of(events);
    let agent = packer.agent_identity(&session);

    let triggers: Vec<(usize, SampleReason)> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| Some((index, reason_of(event, start_ts)?)))
        .collect();
    if triggers.is_empty() {
        return Vec::new();
    }

    // Windows that overlap or touch become one sample, so a burst of
    // questions produces one extract and not twenty near-copies.
    let last = events.len() - 1;
    let mut groups: Vec<(usize, usize, Vec<SampleReason>)> = Vec::new();
    for (index, reason) in triggers {
        let start = index.saturating_sub(options.window);
        let end = (index + options.window).min(last);
        match groups.last_mut() {
            Some(group) if start <= group.1.saturating_add(1) => {
                group.1 = group.1.max(end);
                group.2.push(reason);
            }
            _ => groups.push((start, end, vec![reason])),
        }
    }

    let mut samples = Vec::new();
    for (start, end, reasons) in groups {
        let mut window_events = Vec::new();
        let mut pids: BTreeSet<af_core::Pid> = BTreeSet::new();
        for event in &events[start..=end] {
            window_events.push(packer.event_value(event));
            collect_pids(event, &mut pids);
        }
        samples.push(Sample {
            schema: SAMPLE_SCHEMA.to_string(),
            session: session_ref.clone(),
            consent: consent
                .granted()
                .iter()
                .map(|s| s.label().to_string())
                .collect(),
            agent: agent.clone(),
            reasons,
            tree: nodes_for(&pids, &tree_map, &mut packer.pseu, consent),
            events: window_events,
        });
    }
    samples
}

/// Returns the default outbox directory:
/// `${XDG_DATA_HOME:-$HOME/.local/share}/agent-firewall/outbox`.
pub fn default_outbox_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local"))
                .map(|local| local.join("share"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("agent-firewall").join("outbox")
}

/// Writes one sample into the outbox directory and returns its path.
///
/// The file is pretty JSON, so a text editor is a complete inspector. The
/// name counts the samples of one session: `sample-<session>-001.json`.
pub fn write_sample(dir: &Path, sample: &Sample) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let prefix = format!("sample-{}-", sample.session);
    let mut next = 1u32;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(rest) = name.strip_prefix(&prefix) {
            if let Some(number) = rest.strip_suffix(".json") {
                if let Ok(seen) = number.parse::<u32>() {
                    next = next.max(seen + 1);
                }
            }
        }
    }
    let path = dir.join(format!("{prefix}{next:03}.json"));
    let text = serde_json::to_string_pretty(sample)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    std::fs::write(&path, text.as_bytes())?;
    Ok(path)
}

/// Lists the sample files of an outbox directory, sorted by name.
pub fn list_samples(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Finds the session metadata of a trace, or makes a replacement.
fn session_of(events: &[Event]) -> SessionMeta {
    for event in events {
        if let EventKind::SessionStart { meta, .. } = &event.kind {
            return (**meta).clone();
        }
    }
    let mut meta = SessionMeta::new(vec!["unknown".to_string()], ".".to_string());
    meta.session_id = events[0].session_id.clone();
    meta
}

/// Returns the trigger of one event, when the event is one.
fn reason_of(event: &Event, start_ts: u64) -> Option<SampleReason> {
    let (kind, rule) = match &event.kind {
        EventKind::QuarantineStarted { rule, .. } => ("quarantine_started", Some(rule.clone())),
        EventKind::ApprovalRequested { rule_id, .. } => {
            ("approval_requested", Some(rule_id.clone()))
        }
        EventKind::Tamper { .. } => ("tamper", None),
        EventKind::Discrepancy { .. } => ("discrepancy", None),
        EventKind::SignalSend { .. } => ("signal_send", None),
        EventKind::PolicyDecision { verdict, .. } if verdict.decision != Decision::Allow => (
            "policy_decision",
            verdict.top_match().map(|matched| matched.rule_id.clone()),
        ),
        _ => return None,
    };
    Some(SampleReason {
        kind: kind.to_string(),
        rule,
        at_ms: event.ts.saturating_sub(start_ts) / 1_000_000,
    })
}

/// References every process identifier an event names, in order.
fn pre_scan(event: &Event, pseu: &mut Pseudonyms) {
    if event.pid != 0 {
        pseu.pid(event.pid);
    }
    match &event.kind {
        EventKind::ProcessFork { child_pid, .. } => {
            pseu.pid(*child_pid);
        }
        EventKind::ProcessExec { process } | EventKind::ProcessUnlinked { process, .. } => {
            process_pids(process, pseu);
        }
        EventKind::ProcessExit { sid: Some(sid), .. } => {
            pseu.pid(*sid);
        }
        EventKind::SignalSend { target, .. } => {
            pseu.pid(*target);
        }
        EventKind::PolicyDecision { ancestry, .. } => {
            for process in ancestry {
                process_pids(process, pseu);
            }
        }
        EventKind::SessionStart { meta, .. } => {
            if meta.monitor_pid != 0 {
                pseu.pid(meta.monitor_pid);
            }
            if meta.root_pid != 0 {
                pseu.pid(meta.root_pid);
            }
            if let Some(sensor) = &meta.sensor {
                for instance in &sensor.instances {
                    pseu.pid(*instance);
                }
            }
        }
        _ => {}
    }
}

/// References the identifiers of one process record.
fn process_pids(process: &ProcessInfo, pseu: &mut Pseudonyms) {
    pseu.pid(process.pid);
    if let Some(ppid) = process.ppid {
        pseu.pid(ppid);
    }
    if let Some(sid) = process.sid {
        pseu.pid(sid);
    }
}

/// Collects the identifiers an event names into a set.
fn collect_pids(event: &Event, pids: &mut BTreeSet<af_core::Pid>) {
    let mut single = |pid: af_core::Pid| {
        if pid != 0 {
            pids.insert(pid);
        }
    };
    single(event.pid);
    match &event.kind {
        EventKind::ProcessFork { child_pid, .. } => single(*child_pid),
        EventKind::ProcessExec { process } | EventKind::ProcessUnlinked { process, .. } => {
            single(process.pid);
            if let Some(ppid) = process.ppid {
                single(ppid);
            }
        }
        EventKind::ProcessExit { sid: Some(sid), .. } => {
            single(*sid);
        }
        EventKind::SignalSend { target, .. } => single(*target),
        EventKind::PolicyDecision { ancestry, .. } => {
            for process in ancestry {
                single(process.pid);
                if let Some(ppid) = process.ppid {
                    single(ppid);
                }
            }
        }
        EventKind::SessionStart { meta, .. } => {
            single(meta.monitor_pid);
            single(meta.root_pid);
        }
        _ => {}
    }
}

/// Builds the process table of a trace from its exec events, its fork
/// edges and its ancestry lists.
fn tree_of(events: &[Event]) -> BTreeMap<af_core::Pid, ProcessInfo> {
    let mut tree: BTreeMap<af_core::Pid, ProcessInfo> = BTreeMap::new();
    for event in events {
        match &event.kind {
            EventKind::ProcessFork { child_pid, .. } => {
                // A child that the firewall denied never exec'd, so the fork
                // edge is the only parent link it will ever get.
                let child = tree.entry(*child_pid).or_insert_with(|| {
                    let mut process = ProcessInfo::from_pid(*child_pid);
                    process.ppid = Some(event.pid);
                    process
                });
                if child.ppid.is_none() {
                    child.ppid = Some(event.pid);
                }
            }
            EventKind::ProcessExec { process } | EventKind::ProcessUnlinked { process, .. } => {
                tree.insert(process.pid, (**process).clone());
            }
            EventKind::PolicyDecision { ancestry, .. } => {
                for process in ancestry {
                    tree.entry(process.pid).or_insert_with(|| process.clone());
                }
            }
            _ => {}
        }
    }
    tree
}

/// Builds the tree nodes for a window: every process it names, and every
/// ancestor of those processes that the trace knows.
fn nodes_for(
    pids: &BTreeSet<af_core::Pid>,
    tree: &BTreeMap<af_core::Pid, ProcessInfo>,
    pseu: &mut Pseudonyms,
    consent: &Consent,
) -> Vec<ProcessNode> {
    if !consent.allows(Scope::Tree) {
        return Vec::new();
    }
    // Close the set over the parents, so the chain to the session root is
    // complete even when the window shows only its end.
    let mut closed: BTreeSet<af_core::Pid> = pids.clone();
    let mut queue: Vec<af_core::Pid> = pids.iter().copied().collect();
    while let Some(pid) = queue.pop() {
        if let Some(parent) = tree.get(&pid).and_then(|process| process.ppid) {
            if parent != 0 && closed.insert(parent) {
                queue.push(parent);
            }
        }
    }

    let mut nodes: Vec<ProcessNode> = Vec::new();
    for pid in &closed {
        let info = tree.get(pid);
        let reference = pseu.pid(*pid);
        let parent = info
            .and_then(|process| process.ppid)
            .filter(|ppid| *ppid != 0);
        let exe = info
            .and_then(|process| process.exe.as_deref())
            .map(|exe| pseu.path(exe));
        // The hash needs the real path on this machine; the sample carries
        // the pseudonymized one.
        let exe_hash = info
            .and_then(|process| process.exe.as_deref())
            .and_then(hash_file);
        nodes.push(ProcessNode {
            reference,
            parent: parent.map(|parent| pseu.pid(parent)),
            comm: info.map(|process| process.comm.clone()).unwrap_or_default(),
            exe_hash,
            exe,
        });
    }
    nodes.sort_by(|left, right| natural(&left.reference, &right.reference));
    nodes
}

/// Compares `p2` before `p10`, so the tree reads in process order.
fn natural(left: &str, right: &str) -> std::cmp::Ordering {
    let number = |text: &str| {
        text.strip_prefix('p')
            .and_then(|rest| rest.parse::<u32>().ok())
    };
    match (number(left), number(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

/// Hashes one file, when it exists and is not too large.
fn hash_file(path: &str) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    if size > MAX_HASH_BYTES {
        return None;
    }
    let mut hasher = sha256::Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(format!("sha256:{}", sha256::hex(&hasher.finish())))
}

/// Packs events into their redacted sample form.
struct Packer<'a> {
    consent: &'a Consent,
    pseu: Pseudonyms,
    start_ts: u64,
}

impl Packer<'_> {
    /// Returns the milliseconds between the session start and a time stamp.
    fn at_ms(&self, ts: u64) -> u64 {
        ts.saturating_sub(self.start_ts) / 1_000_000
    }

    fn allows(&self, scope: Scope) -> bool {
        self.consent.allows(scope)
    }

    /// Returns the agent identity of the sample header, when granted.
    fn agent_identity(&mut self, session: &SessionMeta) -> Option<AgentIdentity> {
        if !self.allows(Scope::Identity) {
            return None;
        }
        let detection = session.detection.as_ref()?;
        let signals = detection
            .signals
            .iter()
            .map(|signal| SignalLine {
                detector: signal.detector.clone(),
                agent: signal.agent.clone(),
                detail: self.pseu.scrub(&signal.detail),
                confidence: signal.confidence,
            })
            .collect();
        Some(AgentIdentity {
            name: detection.name.clone(),
            confidence: detection.confidence,
            signals,
        })
    }

    /// Packs one event: its time offset, its process, its agent tag and its
    /// redacted body.
    fn event_value(&mut self, event: &Event) -> Value {
        let mut object = Map::new();
        object.insert("at_ms".to_string(), json!(self.at_ms(event.ts)));
        object.insert("process".to_string(), json!(self.pseu.pid(event.pid)));
        if let Some(tag) = &event.agent {
            if let Some(tag) = self.tag_value(tag) {
                object.insert("agent".to_string(), tag);
            }
        }
        let body = self.kind_value(&event.kind);
        if let Some(body) = body.as_object() {
            for (key, value) in body {
                object.insert(key.clone(), value.clone());
            }
        }
        Value::Object(object)
    }

    /// Returns the agent tag of an event, when the scope is granted.
    fn tag_value(&self, tag: &AgentTag) -> Option<Value> {
        if !self.allows(Scope::Identity) {
            return None;
        }
        Some(json!({
            "name": tag.name,
            "confidence": tag.confidence,
            "link": tag.link.label(),
        }))
    }

    /// Packs the body of one event kind.
    fn kind_value(&mut self, kind: &EventKind) -> Value {
        match kind {
            EventKind::SessionStart { meta, capabilities } => {
                let mut body = json!({
                    "type": "session_start",
                    "capabilities": capabilities,
                    "schema_version": meta.schema_version,
                });
                let object = body.as_object_mut().expect("an object");
                if meta.monitor_pid != 0 {
                    object.insert("monitor".into(), json!(self.pseu.pid(meta.monitor_pid)));
                }
                if meta.root_pid != 0 {
                    object.insert("root".into(), json!(self.pseu.pid(meta.root_pid)));
                }
                if let Some(sensor) = &meta.sensor {
                    let instances: Vec<String> = sensor
                        .instances
                        .iter()
                        .map(|pid| self.pseu.pid(*pid))
                        .collect();
                    object.insert(
                        "sensor".into(),
                        json!({"preload": self.pseu.path(&sensor.preload), "instances": instances}),
                    );
                }
                // The baseline never travels: the git remotes of a work tree
                // name a private repository, and no rule needs them here.
                if self.allows(Scope::Tree) {
                    object.insert("cwd".into(), json!(self.pseu.path(&meta.cwd)));
                }
                if self.allows(Scope::Actions) {
                    let command: Vec<String> =
                        meta.command.iter().map(|word| redact_text(word)).collect();
                    object.insert("command".into(), json!(command));
                }
                if self.allows(Scope::Identity) {
                    object.insert("agent_kind".into(), json!(meta.agent.kind.label()));
                }
                body
            }
            EventKind::ProcessFork {
                child_pid,
                is_thread,
            } => json!({
                "type": "process_fork",
                "child": self.pseu.pid(*child_pid),
                "is_thread": is_thread,
            }),
            EventKind::ProcessExec { process } => {
                json!({"type": "process_exec", "process": self.process_value(process)})
            }
            EventKind::ProcessExit { code, signal, sid } => {
                let mut body = json!({"type": "process_exit", "code": code, "signal": signal});
                if let Some(sid) = sid {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("sid".into(), json!(self.pseu.pid(*sid)));
                }
                body
            }
            EventKind::ProcessUnlinked { process, detach } => json!({
                "type": "process_unlinked",
                "process": self.process_value(process),
                "sid": self.pseu.pid(detach.sid),
                "root_sid": self.pseu.pid(detach.root_sid),
            }),
            EventKind::FileOpen { path, write } => {
                let mut body = json!({"type": "file_open", "write": write});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("path".into(), json!(self.pseu.path(path)));
                }
                body
            }
            EventKind::NetworkConnect { addr, port, host } => {
                let mut body = json!({"type": "network_connect", "addr": addr, "port": port});
                if self.allows(Scope::Actions) {
                    if let Some(host) = host {
                        body.as_object_mut()
                            .expect("an object")
                            .insert("host".into(), json!(self.pseu.scrub(host)));
                    }
                }
                body
            }
            EventKind::SignalSend { target, signal } => json!({
                "type": "signal_send",
                "target": self.pseu.pid(*target),
                "signal": signal,
            }),
            EventKind::Tamper { kind, detail } => {
                let mut body = json!({"type": "tamper", "kind": kind});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("detail".into(), json!(self.pseu.scrub(detail)));
                }
                body
            }
            EventKind::Discrepancy { kind, detail } => {
                let mut body = json!({"type": "discrepancy", "kind": kind});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("detail".into(), json!(self.pseu.scrub(detail)));
                }
                body
            }
            EventKind::FileRead { path, data } => {
                let mut body = json!({"type": "file_read"});
                let object = body.as_object_mut().expect("an object");
                if self.allows(Scope::Actions) {
                    object.insert("path".into(), json!(self.pseu.path(path)));
                }
                if self.allows(Scope::Content) {
                    object.insert(
                        "data".into(),
                        json!(cap(&self.pseu.scrub(data), MAX_CONTENT_CHARS)),
                    );
                }
                body
            }
            EventKind::FileDelete { path } => {
                let mut body = json!({"type": "file_delete"});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("path".into(), json!(self.pseu.path(path)));
                }
                body
            }
            EventKind::FileRename { from, to } => {
                let mut body = json!({"type": "file_rename"});
                if self.allows(Scope::Actions) {
                    let object = body.as_object_mut().expect("an object");
                    object.insert("from".into(), json!(self.pseu.path(from)));
                    object.insert("to".into(), json!(self.pseu.path(to)));
                }
                body
            }
            EventKind::LibraryLoad { path } => {
                let mut body = json!({"type": "library_load"});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("path".into(), json!(self.pseu.path(path)));
                }
                body
            }
            EventKind::EnvChange { name, .. } => {
                // The value of an environment change never travels, whatever
                // the scopes say.
                let mut body = json!({"type": "env_change"});
                if self.allows(Scope::Env) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("name".into(), json!(name));
                }
                body
            }
            EventKind::StdinWrite { stream, data } => {
                let mut body = json!({"type": "stdin_write", "stream": stream});
                if self.allows(Scope::Content) {
                    body.as_object_mut().expect("an object").insert(
                        "data".into(),
                        json!(cap(&self.pseu.scrub(data), MAX_CONTENT_CHARS)),
                    );
                }
                body
            }
            EventKind::PolicyDecision {
                action,
                verdict,
                ancestry,
            } => {
                let mut body = json!({
                    "type": "policy_decision",
                    "action": self.action_value(action),
                    "verdict": self.verdict_value(verdict),
                });
                if self.allows(Scope::Tree) {
                    let chain: Vec<Value> = ancestry
                        .iter()
                        .map(|process| {
                            json!({
                                "process": self.pseu.pid(process.pid),
                                "comm": process.comm,
                            })
                        })
                        .collect();
                    body.as_object_mut()
                        .expect("an object")
                        .insert("ancestry".into(), json!(chain));
                }
                body
            }
            EventKind::ApprovalRequested { action, rule_id } => json!({
                "type": "approval_requested",
                "rule": rule_id,
                "action": self.action_value(action),
            }),
            EventKind::ApprovalResolved {
                rule_id,
                outcome,
                waited_ms,
            } => json!({
                "type": "approval_resolved",
                "rule": rule_id,
                "outcome": outcome,
                "waited_ms": waited_ms,
            }),
            EventKind::QuarantineStarted { rule, evidence } => {
                let mut body = json!({"type": "quarantine_started", "rule": rule});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("evidence".into(), json!(self.pseu.scrub(evidence)));
                }
                body
            }
            EventKind::QuarantineResolved { rule, outcome } => json!({
                "type": "quarantine_resolved",
                "rule": rule,
                "outcome": outcome,
            }),
            EventKind::KernelFloor { rules, denied } => {
                let mut body = json!({"type": "kernel_floor", "rules": rules});
                if self.allows(Scope::Actions) {
                    let paths: Vec<Value> = denied
                        .iter()
                        .map(|path| {
                            json!({"prefix": self.pseu.path(&path.prefix), "rule": path.rule})
                        })
                        .collect();
                    body.as_object_mut()
                        .expect("an object")
                        .insert("denied".into(), json!(paths));
                }
                body
            }
            EventKind::KernelDenied { rule, path } => {
                let mut body = json!({"type": "kernel_denied", "rule": rule});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("path".into(), json!(self.pseu.path(path)));
                }
                body
            }
            EventKind::MonitorWarning { message } => {
                json!({"type": "monitor_warning", "message": self.pseu.scrub(message)})
            }
            EventKind::SessionEnd {
                exit_code,
                process_count,
            } => json!({
                "type": "session_end",
                "exit_code": exit_code,
                "process_count": process_count,
            }),
        }
    }

    /// Packs one process record.
    fn process_value(&mut self, process: &ProcessInfo) -> Value {
        let mut body = json!({
            "pid": self.pseu.pid(process.pid),
            "comm": process.comm,
        });
        let object = body.as_object_mut().expect("an object");
        if let Some(ppid) = process.ppid {
            if ppid != 0 {
                object.insert("ppid".into(), json!(self.pseu.pid(ppid)));
            }
        }
        if let Some(sid) = process.sid {
            object.insert("sid".into(), json!(self.pseu.pid(sid)));
        }
        if self.allows(Scope::Tree) {
            if let Some(exe) = &process.exe {
                object.insert("exe".into(), json!(self.pseu.path(exe)));
            }
            if let Some(cwd) = &process.cwd {
                object.insert("cwd".into(), json!(self.pseu.path(cwd)));
            }
            if let Some(dynamic_link) = process.dynamic_link {
                object.insert("dynamic_link".into(), json!(dynamic_link));
            }
        }
        if self.allows(Scope::Actions) {
            let argv: Vec<String> = process.argv.iter().map(|word| redact_text(word)).collect();
            object.insert("argv".into(), json!(argv));
        }
        if self.allows(Scope::Env) {
            // The values of the environment never travel. The names are the
            // payload, and `<redacted>` keeps the shape.
            let env: BTreeMap<&str, &str> = process
                .env
                .keys()
                .map(|name| (name.as_str(), REDACTED))
                .collect();
            object.insert("env".into(), json!(env));
        }
        body
    }

    /// Packs one action of a policy decision or an approval question.
    fn action_value(&mut self, action: &Action) -> Value {
        match action {
            Action::Exec {
                exe,
                program,
                argv,
                cwd,
                env,
            } => {
                let mut body = json!({"action": "exec", "program": program});
                let object = body.as_object_mut().expect("an object");
                if self.allows(Scope::Tree) {
                    if let Some(exe) = exe {
                        object.insert("exe".into(), json!(self.pseu.path(exe)));
                    }
                    if let Some(cwd) = cwd {
                        object.insert("cwd".into(), json!(self.pseu.path(cwd)));
                    }
                }
                if self.allows(Scope::Actions) {
                    let argv: Vec<String> = argv.iter().map(|word| redact_text(word)).collect();
                    object.insert("argv".into(), json!(argv));
                }
                if self.allows(Scope::Env) {
                    let names: Vec<&str> = env.keys().map(|name| name.as_str()).collect();
                    object.insert("env".into(), json!(names));
                }
                body
            }
            Action::FileOpen { path, write } => {
                let mut body = json!({"action": "file_open", "write": write});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("path".into(), json!(self.pseu.path(path)));
                }
                body
            }
            Action::NetworkConnect { host, addr, port } => {
                let mut body = json!({"action": "network_connect", "addr": addr, "port": port});
                if self.allows(Scope::Actions) {
                    if let Some(host) = host {
                        body.as_object_mut()
                            .expect("an object")
                            .insert("host".into(), json!(self.pseu.scrub(host)));
                    }
                }
                body
            }
            Action::Input { source, data } => {
                let mut body = json!({"action": "input", "source": source});
                if self.allows(Scope::Content) {
                    body.as_object_mut().expect("an object").insert(
                        "data".into(),
                        json!(cap(&self.pseu.scrub(data), MAX_CONTENT_CHARS)),
                    );
                }
                body
            }
            Action::SignalSend { target, signal } => json!({
                "action": "signal_send",
                "target": self.pseu.pid(*target),
                "signal": signal,
            }),
            Action::Tamper { kind, detail } => {
                let mut body = json!({"action": "tamper", "kind": kind});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("detail".into(), json!(self.pseu.scrub(detail)));
                }
                body
            }
            Action::Discrepancy { kind, detail } => {
                let mut body = json!({"action": "discrepancy", "kind": kind});
                if self.allows(Scope::Actions) {
                    body.as_object_mut()
                        .expect("an object")
                        .insert("detail".into(), json!(self.pseu.scrub(detail)));
                }
                body
            }
        }
    }

    /// Packs one verdict: what the engine decided and which rules matched.
    fn verdict_value(&mut self, verdict: &Verdict) -> Value {
        let matches: Vec<Value> = verdict
            .matches
            .iter()
            .map(|matched| {
                json!({
                    "rule": matched.rule_id,
                    "category": matched.category,
                    "risk": matched.risk.label(),
                    "decision": matched.decision.label(),
                    "quarantine": matched.quarantine,
                    "reason": self.pseu.scrub(&matched.reason),
                })
            })
            .collect();
        json!({
            "decision": verdict.decision.label(),
            "risk": verdict.risk.label(),
            "matches": matches,
        })
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            home: None,
            host: None,
        }
    }
}
