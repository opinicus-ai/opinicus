//! Session and agent metadata.

use serde::{Deserialize, Serialize};

use crate::{Pid, TimestampNanos};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}
