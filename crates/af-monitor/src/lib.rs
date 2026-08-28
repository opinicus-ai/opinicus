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
//! The monitor has two decision points.
//!
//! The kernel stops a traced process after `execve` loaded the new program
//! image and before that program runs one instruction. The monitor uses that
//! stop as the decision point for a new program. A process that the monitor
//! kills there never runs the dangerous program.
//!
//! A small `seccomp` filter adds the second point. It runs in the kernel and
//! holds a file open with write intent, and every outgoing connection, before
//! the call happens. The monitor then sees what a program does **after** it
//! started, which the exec stop can never show. [`SyscallFilter`] chooses how
//! wide that filter is, and `Off` gives exactly the behaviour of the versions
//! before it existed.
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
mod seccomp;
mod tracer;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use procfs::{DEFAULT_ENV_ALLOWLIST, REDACTED};

/// How much text the monitor reads of one stream or one script by default.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024;

/// Which system calls the kernel filter holds for the monitor.
///
/// The choice is a trade between what the firewall can see and what the
/// session costs. `research/spikes/seccomp-ptrace/FINDINGS.md` measured all
/// three on one machine with one benchmark.
///
/// | Mode | What the monitor sees | Measured cost |
/// | --- | --- | --- |
/// | [`SyscallFilter::WriteOnly`] | an open that can change a file, and every connection | 1.16× to 1.33× |
/// | [`SyscallFilter::AllOpens`] | every open and every connection | 1.33× to 1.92× |
/// | [`SyscallFilter::Off`] | nothing beyond a new program | no cost |
///
/// The difference is not the mechanism, it is the number of times the
/// supervisor has to wake up. A read-only open is 99.7% of the open traffic
/// of a normal build, and the kernel drops all of it in `WriteOnly` because
/// it can test the `flags` argument itself.
///
/// A rule that needs the path of a **read** — a credential file that a
/// program only reads — therefore stays silent under `WriteOnly`, and
/// `policy list` marks it inactive. `AllOpens` wakes those rules and pays for
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyscallFilter {
    /// Hold an open that asks to change the file, and every connection.
    ///
    /// This is the default. It carries every rule about a write and every
    /// rule about a network destination.
    #[default]
    WriteOnly,
    /// Hold every open, a read included, and every connection.
    AllOpens,
    /// Install no filter, and stop at a new program only.
    ///
    /// The session then also keeps its right to gain a privilege, because the
    /// monitor only sets `no_new_privs` when it really installs a filter.
    Off,
}

impl SyscallFilter {
    /// Reads a mode from a command-line value.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "write-only" | "write_only" | "writeonly" | "write" => Some(Self::WriteOnly),
            "all-opens" | "all_opens" | "allopens" | "all" => Some(Self::AllOpens),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    /// Returns the name of the mode, as the command line spells it.
    pub fn label(self) -> &'static str {
        match self {
            Self::WriteOnly => "write-only",
            Self::AllOpens => "all-opens",
            Self::Off => "off",
        }
    }

    /// Returns true when the monitor observes a file open at all.
    pub fn observes_opens(self) -> bool {
        self != Self::Off
    }

    /// Returns true when the monitor observes an open that only reads.
    pub fn observes_read_opens(self) -> bool {
        self == Self::AllOpens
    }
}

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
    /// Which system calls the kernel filter holds for the monitor.
    ///
    /// The filter is installed one time, in the root process, before its
    /// first program runs. It is inherited by every child and it survives
    /// `execve`, so the whole session is covered.
    pub syscall_filter: SyscallFilter,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            cwd: None,
            env_allowlist: Vec::new(),
            capture_input: true,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            syscall_filter: SyscallFilter::default(),
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
    /// Let the process run the new program, or make the system call.
    Continue,
    /// Stop this process before the new program runs.
    ///
    /// The monitor sends `SIGKILL`. The rest of the session continues.
    ///
    /// This is the right answer at an exec stop, where the whole process is
    /// the dangerous thing. At a system-call stop use [`Intercept::Refuse`],
    /// which leaves the program alive with an error it can handle.
    Deny,
    /// Let the system call fail with `EPERM`, and let the process run on.
    ///
    /// The kernel has not made the call yet, so nothing happened. The program
    /// sees an ordinary permission error, exactly as if the file system had
    /// refused it, and it can report that error to the user in its own words.
    ///
    /// At an exec stop this answer means the same as [`Intercept::Deny`],
    /// because there is no call to fail there.
    Refuse,
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

    /// Answers what must happen with an action inside a running program.
    ///
    /// The kernel filter held the process before it opened a file or before
    /// it opened a connection, and the call has not happened yet. The process
    /// holds until this call returns, so the implementation can ask the user.
    ///
    /// `pid` names the process that acts, and `ancestry` names its parents,
    /// the nearest parent first. The monitor does not read `/proc` again for
    /// this stop, because a session makes many of them; the caller already
    /// knows the process from its exec event.
    ///
    /// The `action` is always an [`af_core::Action::FileOpen`] or an
    /// [`af_core::Action::NetworkConnect`].
    ///
    /// # A path is not proof
    ///
    /// The path and the address inside `action` were read out of the memory
    /// of the process that is being judged. A second thread of that process
    /// can change that memory before the kernel reads it again. The value is
    /// therefore sound for a report, for [`Intercept::Refuse`] and for a
    /// question to the user, and it must never be the reason to **allow**
    /// something that would otherwise be stopped.
    fn on_syscall(
        &mut self,
        pid: af_core::Pid,
        action: &af_core::Action,
        ancestry: &[af_core::Pid],
    ) -> Intercept {
        let _ = (pid, action, ancestry);
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
    ///
    /// `filter` is the mode that the session will use. It changes the answer,
    /// because a mode that does not hold a read-only open cannot report one.
    pub fn capabilities(filter: SyscallFilter) -> Vec<af_core::MonitorCapability> {
        caps::capabilities(filter)
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
