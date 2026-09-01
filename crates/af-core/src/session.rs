//! Session and agent metadata.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::identity::IdentifiedAgent;
use crate::{Pid, TimestampNanos};

/// What the firewall installed inside the processes of this session.
///
/// This is requirement B.5 of `docs/DETECTION-REQUIREMENTS.md`: the facts
/// that a tamper or correlation rule keys on are facts of the firewall's own
/// identity, never of a foreign process. A session that the launcher starts
/// without the in-process sensor carries `None`, and every rule that asks for
/// sensor instances then answers nothing — which is the quiet, correct
/// answer for a normal session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorMeta {
    /// The preload value that carried the sensor into the session root.
    ///
    /// The launcher read it from its own environment. A child whose exec
    /// environment holds no copy of this value has answered a question by
    /// removing the instrument.
    pub preload: String,
    /// The sensor instances that had registered when the session started.
    ///
    /// The list is a snapshot of the registration record of the in-process
    /// sensor (`research/spikes/inprocess/`), taken once at launch. Whether
    /// an instance still speaks is the correlation question of a later
    /// milestone; this list only names what the firewall itself installed.
    #[serde(default)]
    pub instances: Vec<Pid>,
    /// Path of the sensor's own trace file, when it has one.
    ///
    /// The launcher read the path from `AF_SENSOR_TRACE` of its own
    /// environment. The sensor appends every semantic event to this file,
    /// so a write-open of it from a process of the session touches the
    /// evidence of the firewall itself — an audit-trail fact in the shape
    /// of [`SessionMeta::trace`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
    /// Path of the registration record the sensor appends to.
    ///
    /// The launcher read the path from `AF_SENSOR_REG`. The record names
    /// every sensor instance of the session, so it is the other half of the
    /// sensor's own evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<String>,
}

/// Which firewall-owned evidence file a path names.
///
/// These are the B.5 facts of the audit trail (`[af-9]`, SC evade-25): the
/// files that the firewall itself opened — the launcher, never a process of
/// the session — so a rule that keys on them never fires on the writes of a
/// normal session, which opens none of them. The words are what the rule
/// file writes under `evidence_target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// The trace file that this session's recorder writes to.
    Trace,
    /// The trace file of the in-process sensor.
    SensorTrace,
    /// The registration record of the in-process sensor.
    SensorRegistration,
}

impl EvidenceKind {
    /// Returns the label that the rule file and the trace use.
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceKind::Trace => "trace",
            EvidenceKind::SensorTrace => "sensor_trace",
            EvidenceKind::SensorRegistration => "sensor_registration",
        }
    }

    /// Reads one word of the rule file under `evidence_target`.
    ///
    /// The words are the labels, so a rule file and a trace agree on the
    /// name of every fact.
    pub fn from_rule_word(word: &str) -> Result<Self, String> {
        match word {
            "trace" => Ok(EvidenceKind::Trace),
            "sensor_trace" => Ok(EvidenceKind::SensorTrace),
            "sensor_registration" => Ok(EvidenceKind::SensorRegistration),
            other => Err(format!(
                "accepts trace, sensor_trace or sensor_registration, but it got `{other}`"
            )),
        }
    }
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Identifier of one monitored session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl SessionId {
    /// Makes a new identifier from the current time and the monitor process.
    ///
    /// The value only needs to be unique on one machine, so no external
    /// random-number crate is necessary.
    pub fn generate() -> Self {
        let nanos = crate::now_nanos();
        let pid = std::process::id();
        SessionId(format!("afw-{nanos:x}-{pid:x}"))
    }

    /// Returns the identifier as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SessionId {
    fn from(value: &str) -> Self {
        SessionId(value.to_string())
    }
}

/// Which coding agent the session monitors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// OpenAI Codex CLI.
    Codex,
    /// Anthropic Claude Code.
    ClaudeCode,
    /// GitHub Copilot CLI.
    CopilotCli,
    /// Google Gemini CLI.
    GeminiCli,
    /// OpenCode.
    OpenCode,
    /// Pi.
    Pi,
    /// A plain shell or another program.
    Shell,
    /// An agent that the firewall does not recognize.
    Unknown(String),
}

impl AgentKind {
    /// Guesses the agent from the program name of the launched command.
    pub fn detect(program: &str) -> Self {
        match program {
            "codex" => AgentKind::Codex,
            "claude" | "claude-code" => AgentKind::ClaudeCode,
            "copilot" => AgentKind::CopilotCli,
            "gemini" => AgentKind::GeminiCli,
            "opencode" => AgentKind::OpenCode,
            "pi" => AgentKind::Pi,
            "sh" | "bash" | "zsh" | "fish" | "dash" => AgentKind::Shell,
            other => AgentKind::Unknown(other.to_string()),
        }
    }

    /// Maps the agent name of a detection onto a kind.
    ///
    /// The detectors name agents by string (`claude-code`, `gemini-cli`),
    /// because a new agent is a table entry and not a new variant here. An
    /// agent with no variant of its own is [`AgentKind::Unknown`] with its
    /// name, which the user interface shows unchanged.
    pub fn from_agent_name(name: &str) -> Self {
        match name {
            "claude-code" => AgentKind::ClaudeCode,
            "codex" => AgentKind::Codex,
            "copilot-cli" => AgentKind::CopilotCli,
            "gemini-cli" => AgentKind::GeminiCli,
            "opencode" => AgentKind::OpenCode,
            "pi" => AgentKind::Pi,
            other => AgentKind::Unknown(other.to_string()),
        }
    }

    /// Returns a label for the user interface.
    pub fn label(&self) -> &str {
        match self {
            AgentKind::Codex => "Codex",
            AgentKind::ClaudeCode => "Claude Code",
            AgentKind::CopilotCli => "Copilot CLI",
            AgentKind::GeminiCli => "Gemini CLI",
            AgentKind::OpenCode => "OpenCode",
            AgentKind::Pi => "Pi",
            AgentKind::Shell => "shell",
            AgentKind::Unknown(name) => name,
        }
    }
}

/// What the firewall knows about the monitored agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMeta {
    /// Which agent the session monitors.
    pub kind: AgentKind,
    /// Version of the agent, when an adapter can read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Session identifier that the agent itself uses, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    /// Identifier of the tool call that caused the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl AgentMeta {
    /// Makes metadata for an agent that only the program name identifies.
    pub fn from_program(program: &str) -> Self {
        Self {
            kind: AgentKind::detect(program),
            version: None,
            agent_session_id: None,
            tool_call_id: None,
        }
    }
}

/// Metadata of one monitored session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    /// Identifier of the session.
    pub session_id: SessionId,
    /// Time when the session started.
    pub started_at: TimestampNanos,
    /// Identifier of the root process of the session.
    pub root_pid: Pid,
    /// Command that the launcher started.
    pub command: Vec<String>,
    /// Working directory of the root process.
    pub cwd: String,
    /// What the firewall knows about the agent.
    pub agent: AgentMeta,
    /// Version of the event schema of this session.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Named sets of text that the launcher read at session start.
    ///
    /// The launcher records, for example, the git remotes of the work tree
    /// under the name `git_remotes`. A rule can then ask whether a value is
    /// new. The sets travel inside the `SessionStart` event, so a replay
    /// rebuilds the same baseline from the trace and never reads the machine
    /// again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub baseline: BTreeMap<String, BTreeSet<String>>,
    /// The agent the detectors identified in the root command, when they did.
    ///
    /// The launcher assesses the root command once, at session start, with
    /// the built-in detector registry of [`crate::identity`]. The assessment
    /// travels inside the `SessionStart` event, so a replay reads the same
    /// identity from the trace and never detects again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<IdentifiedAgent>,
    /// Process identifier of the monitor itself.
    ///
    /// This is the fact a tamper rule keys on: a signal whose target is this
    /// process is an attempt on the firewall, whatever program sends it. The
    /// value travels inside the `SessionStart` event, so a replay answers the
    /// same question from the trace. Zero means the launcher did not name
    /// itself, which is the case in every trace of an older version.
    #[serde(default)]
    pub monitor_pid: Pid,
    /// The in-process sensor this session runs with, when it runs with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<SensorMeta>,
    /// Path of the trace file that this session's recorder writes to.
    ///
    /// This is a B.5 fact of the audit trail (`[af-9]`): the launcher opened
    /// the file itself, before the session ran, so a write-open of the path
    /// from a process of the session touches the evidence of the firewall
    /// itself, whatever the program is called. The value travels inside the
    /// `SessionStart` event, so a replay answers the same question from the
    /// trace. A session that writes no trace file carries `None`, and every
    /// rule that keys on the fact then answers nothing — the quiet, correct
    /// answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
}

fn default_schema_version() -> u32 {
    crate::EVENT_SCHEMA_VERSION
}

impl SessionMeta {
    /// Makes session metadata for a command that the launcher is about to run.
    pub fn new(command: Vec<String>, cwd: String) -> Self {
        let program = command
            .first()
            .map(|c| c.rsplit('/').next().unwrap_or(c.as_str()).to_string())
            .unwrap_or_default();
        Self {
            session_id: SessionId::generate(),
            started_at: crate::now_nanos(),
            root_pid: 0,
            command,
            cwd,
            agent: AgentMeta::from_program(&program),
            schema_version: crate::EVENT_SCHEMA_VERSION,
            baseline: BTreeMap::new(),
            detection: None,
            monitor_pid: 0,
            sensor: None,
            trace: None,
        }
    }

    /// Returns true when this process is the monitor itself.
    pub fn is_monitor(&self, pid: Pid) -> bool {
        self.monitor_pid != 0 && pid == self.monitor_pid
    }

    /// Returns true when this process is the root of the session.
    pub fn is_session_root(&self, pid: Pid) -> bool {
        self.root_pid != 0 && pid == self.root_pid
    }

    /// Returns true when this process carries a sensor instance that the
    /// firewall installed.
    pub fn is_sensor_instance(&self, pid: Pid) -> bool {
        self.sensor
            .as_ref()
            .is_some_and(|sensor| sensor.instances.contains(&pid))
    }

    /// Returns which firewall-owned evidence file this path names, when it
    /// names one.
    ///
    /// The comparison is on the absolute path string that the session
    /// recorded, never on the file system: a rule asks this question at an
    /// open stop, where the string is what the kernel was about to use. A
    /// path that reaches the same file through another shape — a symlink, a
    /// bind mount, a hard link under another name — answers `None`, and the
    /// honest name for that is a gap, not a fact.
    pub fn evidence_kind(&self, path: &str) -> Option<EvidenceKind> {
        if self.trace.as_deref() == Some(path) {
            return Some(EvidenceKind::Trace);
        }
        let sensor = self.sensor.as_ref()?;
        if sensor.trace.as_deref() == Some(path) {
            return Some(EvidenceKind::SensorTrace);
        }
        if sensor.registration.as_deref() == Some(path) {
            return Some(EvidenceKind::SensorRegistration);
        }
        None
    }
}
