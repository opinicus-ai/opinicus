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

use crate::tracer::{close_beyond_stdio, TRACE_OPTIONS};
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

    caps.push(probe_kernel_floor());

    caps.push(probe_uring_host());

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
        "every open that a 64-bit program asks for with a call of its own reaches the firewall, a read included; a rule about the path of a read can fire"
    } else {
        "only an open that asks to change the file reaches the firewall; a rule that needs the path of a read stays silent, use `--syscall-filter all-opens` for it"
    };
    vec![
        available_with(
            "syscall_filter",
            &format!(
                "a seccomp filter in mode {} holds the calls that a rule can judge; it reads the call table of a 64-bit program, it lets a 32-bit program through with a warning, and it holds io_uring_setup and io_uring_enter in every installed mode, so no ring operation crosses the filter unseen",
                filter.label()
            ),
        ),
        available_with("file_open_events", file_detail),
        available_with(
            "network_events",
            "the outgoing connect of a 64-bit program to an IPv4 or an IPv6 address reaches the firewall when the program makes the call itself; a local socket is passed by",
        ),
    ]
}

/// Reads the host's io_uring posture and reports it as the host-requirement
/// fact it is.
///
/// The filter holds the two ring calls in every installed mode and the
/// built-in rule reports them, but the road itself stays open: a host that
/// must close it at kernel grade sets the sysctl, and the user has to know
/// which state this machine is in (`docs/DECISIONS.md`, 2026-09-01).
fn probe_uring_host() -> MonitorCapability {
    let read = fs::read_to_string("/proc/sys/kernel/io_uring_disabled")
        .ok()
        .and_then(|text| text.trim().parse::<i32>().ok());
    match read {
        Some(0) => available_with(
            "io_uring_host",
            "kernel.io_uring_disabled is 0: the ring road is open. The firewall holds \
             io_uring_setup and io_uring_enter at the call boundary and reports every \
             call; refusing the road itself is a host requirement — set the sysctl to 2, \
             or load a local rule file that replaces tamper.bypass.io-uring with a deny",
        ),
        Some(1) => available_with(
            "io_uring_host",
            "kernel.io_uring_disabled is 1: this host refuses new io_uring instances for \
             processes without a ring already open, which closes the road at kernel grade",
        ),
        Some(2) => available_with(
            "io_uring_host",
            "kernel.io_uring_disabled is 2: this host refuses io_uring for every process \
             without CAP_SYS_ADMIN — the road is closed at kernel grade",
        ),
        other => MonitorCapability::missing(
            "io_uring_host",
            format!(
                "cannot read the io_uring posture of this kernel ({}); the firewall holds \
                 and reports the ring calls anyway",
                other
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unreadable".into())
            ),
        ),
    }
}

/// Reports whether this machine can carry the kernel floor.
///
/// The floor is independent of the filter mode: it enforces the "always no"
/// rule classes of the built-in pack in the kernel, whatever else the session
/// observes. A machine that says no keeps asking those rules exactly as
/// before, and the probe says so.
fn probe_kernel_floor() -> MonitorCapability {
    match crate::landlock::availability() {
        Ok(abi) => available_with(
            "kernel_floor",
            &format!(
                "Landlock ABI {abi}: the always-no rule classes of the built-in pack are \
                 enforced by the kernel before the first program runs, with no question"
            ),
        ),
        Err(reason) => MonitorCapability::missing(
            "kernel_floor",
            format!("{reason}; the rule classes it carries keep asking as before"),
        ),
    }
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
    // SAFETY: the closure only calls ptrace and marks flags of descriptors
    // of the forked child, which are safe in a forked child. The probe gets
    // the same launch hygiene as a session: nothing beyond stdio survives
    // its `execve`.
    unsafe {
        command.pre_exec(|| {
            ptrace::traceme().map_err(std::io::Error::from)?;
            close_beyond_stdio();
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start a test process: {error}"))?;
    let pid = NixPid::from_raw(child.id() as i32);

    let result = probe_steps(pid);

    let _ = kill(pid, Signal::SIGKILL);
    reap_probe(pid);
    result
}

/// Walks the probe process to its final exit and reaps that exit.
///
/// The trace options carry `PTRACE_O_TRACEEXIT`, so a probe that reached its
/// own end stops once more before it dies. Taking that stop without letting
/// the process continue would leave it half-dead: the next monitor session
/// of the same process — the test program — would reap its exit with
/// `waitpid(-1)` and report a process that never belonged to it. The loop
/// answers an exit stop with a continue and waits for the real exit, so no
/// state of the probe outlives the probe.
fn reap_probe(pid: NixPid) {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL)) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(WaitStatus::PtraceEvent(_, _, event))
                if event == ptrace::Event::PTRACE_EVENT_EXIT as i32 =>
            {
                // The stop before the end. Only a continue lets the process
                // die, and only the exit after it is the final status.
                let _ = ptrace::cont(pid, None);
            }
            Ok(_) => return,
            Err(Errno::EINTR) => {}
            // No child left: something else reaped the exit already.
            Err(Errno::ECHILD) => return,
            Err(_) => return,
        }
        if Instant::now() >= deadline {
            return;
        }
        sleep(Duration::from_millis(1));
    }
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
