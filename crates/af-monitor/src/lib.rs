//! Linux user-space monitor of a coding-agent process tree.
//!
//! The monitor launches one command and follows every descendant process. It
//! converts what it observes into the normalized events of `af-core`, and it
//! gives the caller one synchronous chance to stop a process before the new
//! program of that process runs.
//!
//! The monitor needs no root account, no kernel module and no container. It
//! uses only `ptrace` and the `/proc` file system.
//!
//! # How the interception works
//!
//! The kernel stops a traced process after `execve` loaded the new program
//! image and before that program runs one instruction. The monitor uses that
//! stop as the decision point. A process that the monitor kills there never
//! runs the dangerous program.
//!
//! # Example
//!
//! ```no_run
//! use af_core::SessionMeta;
//! use af_monitor::{Intercept, Monitor, MonitorConfig, MonitorHandler};
//!
//! struct Guard;
//!
//! impl MonitorHandler for Guard {
//!     fn on_event(&mut self, event: af_core::Event) {
//!         println!("{}", event.kind_label());
//!     }
//!
//!     fn on_exec(
//!         &mut self,
//!         process: &af_core::ProcessInfo,
//!         _ancestry: &[af_core::Pid],
//!         _input: Option<&af_monitor::InputSnapshot>,
//!     ) -> Intercept {
//!         if process.program_name() == "shred" {
//!             return Intercept::Deny;
//!         }
//!         Intercept::Continue
//!     }
//! }
//!
//! let command = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
//! let config = MonitorConfig::new(command);
//! let session = SessionMeta::new(config.command.clone(), ".".to_string());
//! let outcome = Monitor::run(&config, &session, &mut Guard).unwrap();
//! println!("exit code {:?}", outcome.exit_code);
//! ```

#![deny(missing_docs)]

pub mod inspect;

mod caps;
mod procfs;
mod tracer;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use procfs::{DEFAULT_ENV_ALLOWLIST, REDACTED};

/// How much text the monitor reads of one stream or one script by default.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024;

/// What the monitor must launch and how much it must read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorConfig {
    /// Program and arguments of the session. The list is never empty.
    pub command: Vec<String>,
    /// Working directory of the root process. `None` keeps the current one.
    pub cwd: Option<PathBuf>,
    /// Extra environment names that the monitor keeps.
    ///
    /// The monitor always keeps the names of [`DEFAULT_ENV_ALLOWLIST`]. It
    /// replaces the value of a name that looks like a secret with
    /// [`REDACTED`], but it keeps the name.
    pub env_allowlist: Vec<String>,
    /// True when the monitor reads standard input and script files at exec.
    pub capture_input: bool,
    /// Highest number of bytes that the monitor reads of one input.
    pub max_input_bytes: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            cwd: None,
            env_allowlist: Vec::new(),
            capture_input: true,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

impl MonitorConfig {
    /// Makes a configuration for one command.
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            ..Default::default()
        }
    }
}

/// What the caller wants the monitor to do with a held process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intercept {
    /// Let the process run the new program.
    Continue,
    /// Stop this process before the new program runs.
    ///
    /// The monitor sends `SIGKILL`. The rest of the session continues.
    Deny,
    /// Stop this process and every other process of the session.
    TerminateSession,
}

/// Text that the monitor read around one exec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSnapshot {
    /// Content behind file descriptor 0, when that descriptor can be read.
    ///
    /// The value is `None` for a pipe, a socket and a terminal, because such
    /// a stream holds no stored content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Content of the script that the process runs, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
}

impl InputSnapshot {
    /// Returns true when the monitor could read nothing.
    pub fn is_empty(&self) -> bool {
        self.stdin.is_none() && self.script.is_none()
    }

    /// Returns every piece of text that the monitor read.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.stdin
            .as_deref()
            .into_iter()
            .chain(self.script.as_deref())
    }
}

/// A receiver of monitor events and the owner of the exec decision.
pub trait MonitorHandler {
    /// Receives one normalized event.
    ///
    /// The sequence number of the event is zero. The event sink of the
    /// recorder gives the events their order.
    fn on_event(&mut self, event: af_core::Event);

    /// Answers what must happen with a process that waits at its exec stop.
    ///
    /// The process holds until this call returns, so the implementation can
    /// ask the user. `ancestry` names the parents of the process, the nearest
    /// parent first and the root of the session last. `input` holds the text
    /// that the monitor read, and is `None` when
    /// [`MonitorConfig::capture_input`] is false.
    fn on_exec(
        &mut self,
        process: &af_core::ProcessInfo,
        ancestry: &[af_core::Pid],
        input: Option<&InputSnapshot>,
    ) -> Intercept {
        let _ = (process, ancestry, input);
        Intercept::Continue
    }
}

/// The result of one monitored session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    /// Exit code of the root process, when it ended normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Signal that ended the root process, when a signal ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// True when the firewall ended the session itself.
    pub terminated_by_firewall: bool,
    /// How many processes the session created, the root included.
    ///
    /// A thread of a program is not a separate process, so the count does not
    /// hold it.
    pub process_count: usize,
}

impl SessionOutcome {
    /// Returns true when the session ended normally with the code zero.
    pub fn is_success(&self) -> bool {
        self.exit_code == Some(0) && self.signal.is_none() && !self.terminated_by_firewall
    }
}

/// The Linux process-tree monitor.
pub struct Monitor;

impl Monitor {
    /// Reports what this machine lets the monitor observe and stop.
    ///
    /// The report comes from a real test on this machine. The function
    /// launches one short process under `ptrace` and checks every step that a
    /// session needs.
    pub fn capabilities() -> Vec<af_core::MonitorCapability> {
        caps::capabilities()
    }

    /// Launches the command and follows it until the whole tree ends.
    ///
    /// The root process keeps the terminal of the user, so an interactive
    /// agent still works. The monitor reads `session` but never changes it.
    /// The identifier of the root process is in the first
    /// [`af_core::EventKind::ProcessExec`] event.
    ///
    /// The call reaps every child of the calling process while it runs, so the
    /// caller must not start another child process at the same time.
    ///
    /// # Errors
    ///
    /// Returns an error when the command is empty, when the program cannot
    /// start, or when the kernel refuses a `ptrace` request.
    pub fn run(
        config: &MonitorConfig,
        session: &af_core::SessionMeta,
        handler: &mut dyn MonitorHandler,
    ) -> af_core::Result<SessionOutcome> {
        tracer::run(config, session, handler)
    }

    /// Reads the facts of a live process from `/proc`.
    ///
    /// Returns `None` when the process no longer exists.
    pub fn read_process(
        pid: af_core::Pid,
        env_allowlist: &[String],
    ) -> Option<af_core::ProcessInfo> {
        procfs::read_process(pid, env_allowlist)
    }
}
