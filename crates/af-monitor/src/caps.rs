//! Probe of what this machine lets the monitor observe and stop.
//!
//! The probe measures the real machine. It launches one short test process
//! under `ptrace` and checks every step that the monitor needs. It never
//! guesses from the kernel version.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid as NixPid;

use af_core::MonitorCapability;

use crate::tracer::TRACE_OPTIONS;
use crate::{seccomp, SyscallFilter};

/// How long the probe waits for its own test process.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Path of the Yama setting that limits `ptrace` on many distributions.
const YAMA_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Makes a capability record that is available and adds a remark.
fn available_with(name: &str, detail: &str) -> MonitorCapability {
    MonitorCapability {
        name: name.to_string(),
        available: true,
        detail: Some(detail.to_string()),
    }
}

/// Reports what this machine lets the monitor observe and stop.
///
/// `filter` is the mode that the session will use. A mode changes the answer,
/// because the kernel filter decides in the kernel which calls ever reach the
/// monitor at all.
pub fn capabilities(filter: SyscallFilter) -> Vec<MonitorCapability> {
    let mut caps = Vec::new();

    match probe_launch() {
        Ok(()) => {
            caps.push(available_with(
                "process_tree_tracking",
                "ptrace follows fork, vfork and clone, so every descendant stays in the session",
            ));
            caps.push(available_with(
                "exec_interception",
                "the kernel holds a process at the exec stop before the new program runs",
            ));
        }
        Err(reason) => {
            caps.push(MonitorCapability::missing(
                "process_tree_tracking",
                reason.clone(),
            ));
            caps.push(MonitorCapability::missing("exec_interception", reason));
        }
    }

    let self_pid = std::process::id() as af_core::Pid;

    match crate::procfs::read_cmdline(self_pid) {
        Some(_) => caps.push(available_with(
            "argv_capture",
            "read from /proc/<pid>/cmdline",
        )),
        None => caps.push(MonitorCapability::missing(
            "argv_capture",
            "cannot read /proc/<pid>/cmdline on this machine",
        )),
    }

    match crate::procfs::read_cwd(self_pid) {
        Some(_) => caps.push(available_with("cwd_capture", "read from /proc/<pid>/cwd")),
        None => caps.push(MonitorCapability::missing(
            "cwd_capture",
            "cannot read the link /proc/<pid>/cwd on this machine",
        )),
    }

    match fs::read_link(format!("/proc/{self_pid}/fd/0")) {
        Ok(_) => caps.push(available_with(
            "stdin_inspection",
            "only for a regular file behind descriptor 0; a pipe, a socket and a terminal hold no stored content",
        )),
        Err(error) => caps.push(MonitorCapability::missing(
            "stdin_inspection",
            format!("cannot read the link /proc/<pid>/fd/0: {error}"),
        )),
    }

    caps.extend(probe_syscall_filter(filter));

    caps.push(probe_unprivileged());
    caps
}

/// Reports what the kernel filter of this session can observe.
///
/// The probe asks the kernel itself whether it offers the trace action, and
/// it then reports what the chosen mode really watches. It never claims more
/// than the mode gives: a mode that drops a read-only open in the kernel
/// cannot report the read of a credential file, and the user has to know
/// that.
fn probe_syscall_filter(filter: SyscallFilter) -> Vec<MonitorCapability> {
    if filter == SyscallFilter::Off {
        let reason =
            "the option `--syscall-filter off` switched the kernel filter off for this session";
        return vec![
            MonitorCapability::missing("syscall_filter", reason),
            MonitorCapability::missing("file_open_events", reason),
            MonitorCapability::missing("network_events", reason),
        ];
    }

    if let Err(reason) = seccomp::availability() {
        return vec![
            MonitorCapability::missing("syscall_filter", reason.clone()),
            MonitorCapability::missing("file_open_events", reason.clone()),
            MonitorCapability::missing("network_events", reason),
        ];
    }

    let file_detail = if filter.observes_read_opens() {
        "every open reaches the firewall, a read included; a rule about the path of a read can fire"
    } else {
        "only an open that asks to change the file reaches the firewall; a rule that needs the path of a read stays silent, use `--syscall-filter all-opens` for it"
    };
    vec![
        available_with(
            "syscall_filter",
            &format!(
                "a seccomp filter in mode {} holds the calls that a rule can judge",
                filter.label()
            ),
        ),
        available_with("file_open_events", file_detail),
        available_with(
            "network_events",
            "every outgoing connection to an IPv4 or an IPv6 address reaches the firewall; a local socket is passed by",
        ),
    ]
}

/// Reads the Yama setting and reports whether a normal user can trace.
fn probe_unprivileged() -> MonitorCapability {
    let scope = match fs::read_to_string(YAMA_PATH) {
        Ok(text) => text.trim().parse::<i32>().unwrap_or(-1),
        Err(_) => {
            return available_with(
                "unprivileged",
                "Yama is not active on this machine, so no extra privilege is needed",
            )
        }
    };
    match scope {
        0 => available_with("unprivileged", "yama ptrace_scope is 0: any process may trace"),
        1 => available_with(
            "unprivileged",
            "yama ptrace_scope is 1: a process may trace its own descendants, which is what the monitor does",
        ),
        2 => available_with(
            "unprivileged",
            "yama ptrace_scope is 2: attach needs CAP_SYS_PTRACE, but a launched descendant may still trace itself",
        ),
        3 => MonitorCapability::missing(
            "unprivileged",
            "yama ptrace_scope is 3: this kernel refuses every ptrace request",
        ),
        other => MonitorCapability::missing(
            "unprivileged",
            format!("yama ptrace_scope has the unknown value {other}"),
        ),
    }
}

/// Launches one short test process and checks the whole trace path.
///
/// The probe stops at the exec of the test program, sets the trace options
/// and lets the program finish. It cleans up in every case.
fn probe_launch() -> Result<(), String> {
    let program = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| "no /bin/true program to test the trace path with".to_string())?;

    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure only calls ptrace, which is safe in a forked child.
    unsafe {
        command.pre_exec(|| ptrace::traceme().map_err(std::io::Error::from));
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start a test process: {error}"))?;
    let pid = NixPid::from_raw(child.id() as i32);

    let result = probe_steps(pid);

    let _ = kill(pid, Signal::SIGKILL);
    let _ = wait_bounded(pid, PROBE_TIMEOUT);
    result
}

/// Runs the single steps of the probe on the test process.
fn probe_steps(pid: NixPid) -> Result<(), String> {
    match wait_bounded(pid, PROBE_TIMEOUT)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
        other => return Err(format!("the test process did not stop at exec: {other:?}")),
    }
    ptrace::setoptions(pid, TRACE_OPTIONS)
        .map_err(|error| format!("the kernel refused the ptrace options: {error}"))?;
    ptrace::cont(pid, None)
        .map_err(|error| format!("the kernel refused to continue a traced process: {error}"))?;
    Ok(())
}

/// Waits for one state change of a process, but never longer than `timeout`.
fn wait_bounded(pid: NixPid, timeout: Duration) -> Result<WaitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL)) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(status) => return Ok(status),
            Err(Errno::EINTR) => {}
            Err(error) => return Err(format!("waitpid failed: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("the test process did not answer in time".to_string());
        }
        sleep(Duration::from_millis(1));
    }
}
