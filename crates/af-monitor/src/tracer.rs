//! The `ptrace` event loop that follows a whole process tree.
//!
//! The loop launches one command, follows every descendant, and holds each
//! process at two moments.
//!
//! The first is the moment the kernel loaded a new program but did not yet
//! run one instruction of it. That is the point where the firewall can still
//! stop a dangerous program.
//!
//! The second is the moment a running program asks the kernel for something
//! that a rule can judge: a file open that can change the file, or an
//! outgoing connection. A `seccomp` filter picks those calls out in the
//! kernel and the loop meets them at a `PTRACE_EVENT_SECCOMP` stop. See
//! [`crate::seccomp`] for the filter and for the limits of what it proves.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid as NixPid;

use af_core::{
    Action, Error, Event, EventKind, InputStream, Pid, ProcessInfo, Result, SessionMeta,
};

use crate::{
    procfs, seccomp, InputSnapshot, Intercept, LandlockMode, MonitorConfig, MonitorHandler,
    SessionOutcome, SyscallFilter,
};

/// Trace options that the monitor uses for every process of the tree.
///
/// `PTRACE_O_EXITKILL` is important for safety. It tells the kernel to kill
/// every traced process when the monitor dies, so no process of the tree ever
/// stays stopped without a monitor.
///
/// `PTRACE_O_TRACESECCOMP` is what brings a held system call to this loop.
/// The option costs nothing when no filter is installed, because the kernel
/// then never answers `SECCOMP_RET_TRACE`.
pub const TRACE_OPTIONS: ptrace::Options = ptrace::Options::PTRACE_O_TRACEFORK
    .union(ptrace::Options::PTRACE_O_TRACEVFORK)
    .union(ptrace::Options::PTRACE_O_TRACECLONE)
    .union(ptrace::Options::PTRACE_O_TRACEEXEC)
    .union(ptrace::Options::PTRACE_O_TRACEEXIT)
    .union(ptrace::Options::PTRACE_O_TRACESECCOMP)
    .union(ptrace::Options::PTRACE_O_EXITKILL);

/// Highest depth that the ancestry walk accepts.
///
/// The parent map can never hold a cycle, but a guard keeps the monitor safe
/// against damaged data.
const MAX_ANCESTRY: usize = 256;

/// Programs that ask the kernel to raise the privilege of the user.
///
/// None of them can work inside a traced session, and the error that they
/// print names neither the firewall nor the reason. The monitor says it
/// itself, so the user does not blame the program.
const PRIVILEGE_PROGRAMS: [&str; 4] = ["sudo", "su", "passwd", "pkexec"];

/// State of one traced session.
struct Tracer<'a> {
    config: &'a MonitorConfig,
    session: &'a SessionMeta,
    handler: &'a mut dyn MonitorHandler,
    root: Pid,
    /// Processes that still have to report their end.
    tracked: HashSet<Pid>,
    /// Every process that the session ever created.
    known: HashSet<Pid>,
    /// Tasks of `known` that are a thread and not a separate process.
    threads: HashSet<Pid>,
    /// Parent of each process, so the monitor can build the ancestry.
    parents: HashMap<Pid, Pid>,
    /// Processes for which a fork event is already out.
    forked: HashSet<Pid>,
    /// Processes for which an exit event is already out.
    exited: HashSet<Pid>,
    /// Processes that already got the warning about a foreign call table.
    warned_abi: HashSet<Pid>,
    terminated: bool,
    root_code: Option<i32>,
    root_signal: Option<i32>,
    /// The filter mode that this session really got.
    ///
    /// It is [`SyscallFilter::Off`] when the machine cannot carry the filter,
    /// whatever the configuration asked for.
    filter: SyscallFilter,
    /// Why the session did not get the filter that it asked for.
    ///
    /// The loop reports it one time, as a warning event, before it starts.
    filter_warning: Option<String>,
    /// The kernel floor of this session, when one was enacted.
    ///
    /// The plan is `None` when the mode said off, when the machine cannot
    /// carry Landlock, or when the child reported that the kernel refused the
    /// ruleset. Only a session that really enacted the floor explains its
    /// denials and lets the kernel answer the questions the floor carries.
    floor: Option<crate::landlock::Plan>,
    /// Why the session got no kernel floor.
    ///
    /// The loop reports it one time, as a warning event, before it starts.
    floor_warning: Option<String>,
    /// The read end of the report pipe of the floor, until the loop read it.
    floor_report: Option<std::fs::File>,
}

/// Launches the command and follows it until the whole tree ends.
pub fn run(
    config: &MonitorConfig,
    session: &SessionMeta,
    handler: &mut dyn MonitorHandler,
) -> Result<SessionOutcome> {
    let Some(program) = config.command.first() else {
        return Err(Error::monitor("the command of the session is empty"));
    };

    // The machine decides whether the kernel filter can run at all. A machine
    // that says no keeps the exec boundary and the session goes on; the
    // firewall must never fail because it cannot see everything.
    let (filter, filter_warning) = match config.syscall_filter {
        SyscallFilter::Off => (SyscallFilter::Off, None),
        wanted => match seccomp::availability() {
            Ok(()) => (wanted, None),
            Err(reason) => (SyscallFilter::Off, Some(reason)),
        },
    };

    // The kernel floor is built here, in the monitor, from the working
    // directory and the home directory of the user. The child only enacts a
    // plan that already exists, so no directory is read between fork and
    // execve.
    let (floor, floor_warning) = match config.landlock {
        LandlockMode::Off => (None, None),
        LandlockMode::On => match crate::landlock::availability() {
            Ok(abi) => {
                let work_tree = config
                    .cwd
                    .clone()
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| PathBuf::from("."));
                let home = config
                    .landlock_home
                    .clone()
                    .or_else(|| std::env::var_os("HOME").map(PathBuf::from));
                let plan = crate::landlock::Plan::build(&work_tree, home.as_deref(), abi);
                if plan.rule_count() == 0 {
                    (
                        None,
                        Some("no path of this machine could be granted for the floor".to_string()),
                    )
                } else {
                    (Some(plan), None)
                }
            }
            Err(reason) => (None, Some(reason)),
        },
    };

    // The child cannot report through the return value of the closure, so it
    // writes one byte into this pipe right before its `execve`: zero when it
    // enacted the floor, the errno otherwise. The write end closes at
    // `execve`, and the monitor reads the byte after the first exec stop.
    let mut floor_report_writer = None;
    let mut floor_report_reader = None;
    if floor.is_some() {
        match report_pipe() {
            Ok((read, write)) => {
                floor_report_writer = Some(write);
                floor_report_reader = Some(read);
            }
            Err(error) => {
                return Err(Error::os(format!(
                    "cannot make the report pipe of the kernel floor: {error}"
                )))
            }
        }
    }

    let mut command = Command::new(program);
    command.args(&config.command[1..]);
    if let Some(cwd) = config.cwd.as_ref() {
        command.current_dir(cwd);
    }
    // The child keeps the terminal of the user, so an interactive agent still
    // works while the monitor watches it.
    //
    // The child only asks the kernel to trace it. It does not stop itself with
    // SIGSTOP, because `Command::spawn` waits for the child to reach `execve`
    // before it returns. A child that stops before `execve` would block the
    // monitor thread for ever. The kernel raises SIGTRAP after `execve`
    // instead, which gives the monitor the same first stop.
    //
    // The kernel floor is enacted here, in the child, after the request to
    // be traced and before the filter. It survives `fork` and `execve`, and
    // no descendant can relax it. It never fails the session: the child
    // writes one status byte into the report pipe and the monitor tells the
    // user itself when the floor is absent.
    //
    // The kernel filter is installed last, because its own install must be
    // the last thing before `execve`: the filter holds file opens, and the
    // floor needs one open per rule. With the filter first, every one of
    // those opens answers `ENOSYS` in the `all-opens` mode, because no tracer
    // answers a `RET_TRACE` stop of a child that has not reached its first
    // exec yet (measured: that was the errno 38 the report pipe carried).
    // The filter is inherited by every child and it survives `execve`, so
    // this one install covers the whole session and no descendant can escape
    // it. Its install never fails the session: see `seccomp::install`.
    //
    // SAFETY: the closure only calls ptrace, prctl, seccomp and landlock,
    // which all act on the forked child alone and are safe between fork and
    // exec. It allocates nothing and reads no directory: the plan and the
    // pipe descriptor already exist.
    let install_plan = floor.clone();
    let report_fd = floor_report_writer
        .as_ref()
        .map_or(-1, |file| file.as_raw_fd());
    unsafe {
        command.pre_exec(move || {
            ptrace::traceme().map_err(std::io::Error::from)?;
            if let Some(plan) = install_plan.as_ref() {
                let byte = match plan.install() {
                    Ok(()) => 0u8,
                    Err(error) => error.raw_os_error().unwrap_or(1) as u8,
                };
                if report_fd >= 0 {
                    libc::write(report_fd, &[byte] as *const u8 as *const libc::c_void, 1);
                }
            }
            seccomp::install(filter);
            Ok(())
        });
    }

    let child = command.spawn().map_err(|error| {
        let shown = af_core::display::truncate(&config.command.join(" "), 120);
        Error::monitor(format!("cannot start {shown}: {error}"))
    })?;
    let root = child.id() as Pid;
    // The write end must be gone before the loop reads the report, or a read
    // could wait for a writer that never comes. The child's own copy closed
    // at `execve`.
    drop(floor_report_writer);
    // The caller learns the root process before the first event, so the
    // session metadata that it records can carry the identifier.
    handler.on_session_root(root);

    let mut tracer = Tracer {
        config,
        session,
        handler,
        root,
        tracked: HashSet::from([root]),
        known: HashSet::from([root]),
        threads: HashSet::new(),
        parents: HashMap::new(),
        // The root has no fork event, because the monitor created it itself.
        forked: HashSet::from([root]),
        exited: HashSet::new(),
        warned_abi: HashSet::new(),
        terminated: false,
        root_code: None,
        root_signal: None,
        filter,
        filter_warning,
        floor,
        floor_warning,
        floor_report: floor_report_reader,
    };

    tracer.run_loop()?;
    Ok(tracer.outcome())
}

impl Tracer<'_> {
    /// Waits for the first stop of the root and then follows the whole tree.
    fn run_loop(&mut self) -> Result<()> {
        if let Some(reason) = self.filter_warning.take() {
            self.emit(
                self.root,
                EventKind::MonitorWarning {
                    message: format!(
                        "the firewall observes no file open and no connection: {reason}"
                    ),
                },
            );
        }
        if !self.await_root_start()? {
            return Ok(());
        }
        self.check_filter();
        self.check_floor();
        while !self.tracked.is_empty() {
            let Some(status) = wait_any(None)? else {
                // No child is left. This only happens when another part of the
                // program reaped a process of the tree.
                self.tracked.clear();
                break;
            };
            self.dispatch(status);
        }
        Ok(())
    }

    /// Waits until the root process holds at its first exec.
    ///
    /// Returns `false` when the root already ended.
    fn await_root_start(&mut self) -> Result<bool> {
        let root = NixPid::from_raw(self.root);
        loop {
            let Some(status) = wait_any(Some(root))? else {
                self.tracked.clear();
                return Ok(false);
            };
            match status {
                WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                    ptrace::setoptions(pid, TRACE_OPTIONS).map_err(|error| {
                        Error::os(format!("cannot set the trace options: {error}"))
                    })?;
                    self.handle_exec(self.root);
                    return Ok(true);
                }
                WaitStatus::Stopped(pid, signal) => {
                    self.resume(pid.as_raw(), forwardable(signal));
                }
                WaitStatus::Exited(_, code) => {
                    self.note_exit(self.root, Some(code), None);
                    self.tracked.clear();
                    return Ok(false);
                }
                WaitStatus::Signaled(_, signal, _) => {
                    self.note_exit(self.root, None, Some(signal as i32));
                    self.tracked.clear();
                    return Ok(false);
                }
                _ => {}
            }
        }
    }

    /// Proves that the kernel really holds the filter, and says so when not.
    ///
    /// The child installed the filter itself and had no way to report a
    /// failure, so the only honest proof is the state of the root process
    /// after its first program started. `/proc/<pid>/status` holds it.
    fn check_filter(&mut self) {
        if self.filter == SyscallFilter::Off || seccomp::is_active(self.root) {
            return;
        }
        self.filter = SyscallFilter::Off;
        self.emit(
            self.root,
            EventKind::MonitorWarning {
                message: "the kernel refused the system-call filter, so the firewall observes \
                          no file open and no connection in this session"
                    .to_string(),
            },
        );
    }

    /// Reads what the child reported about the kernel floor.
    ///
    /// The child wrote one byte into the report pipe right before its
    /// `execve`. Zero means the floor is active: the loop tells the handler
    /// which rule classes the kernel now answers, so the session stops asking
    /// them. Anything else is a refusal, and the session goes on without the
    /// floor exactly as it did before the floor existed.
    fn check_floor(&mut self) {
        if let Some(reason) = self.floor_warning.take() {
            self.emit(
                self.root,
                EventKind::MonitorWarning {
                    message: format!("this session runs without the kernel floor: {reason}"),
                },
            );
            return;
        }
        let Some(mut report) = self.floor_report.take() else {
            return;
        };
        let mut byte = [0u8; 1];
        let reported = report.read(&mut byte).ok().filter(|got| *got == 1);

        match reported {
            Some(_) if byte[0] == 0 => {
                let plan = self.floor.as_ref();
                let rules = plan.map(|plan| plan.enforced_rules()).unwrap_or_default();
                let denied = plan
                    .map(|plan| {
                        plan.denied_prefixes()
                            .into_iter()
                            .map(|(prefix, rule)| af_core::KernelDeniedPath {
                                prefix,
                                rule: rule.to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                self.emit(self.root, EventKind::KernelFloor { rules, denied });
            }
            Some(_) => {
                self.floor = None;
                self.emit(
                    self.root,
                    EventKind::MonitorWarning {
                        message: format!(
                            "the kernel refused the kernel floor (errno {}), so this session \
                             runs without it and its rule classes keep asking",
                            byte[0]
                        ),
                    },
                );
            }
            None => {
                self.floor = None;
                self.emit(
                    self.root,
                    EventKind::MonitorWarning {
                        message: "the child reported nothing about the kernel floor, so this \
                                  session runs without it"
                            .to_string(),
                    },
                );
            }
        }
    }

    /// Handles one state change of one process of the tree.
    fn dispatch(&mut self, status: WaitStatus) {
        match status {
            WaitStatus::Exited(pid, code) => {
                self.note_exit(pid.as_raw(), Some(code), None);
                self.tracked.remove(&pid.as_raw());
            }
            WaitStatus::Signaled(pid, signal, _) => {
                self.note_exit(pid.as_raw(), None, Some(signal as i32));
                self.tracked.remove(&pid.as_raw());
            }
            WaitStatus::PtraceEvent(pid, _, event) => {
                self.handle_ptrace_event(pid.as_raw(), event);
            }
            WaitStatus::Stopped(pid, signal) => {
                let raw = pid.as_raw();
                self.adopt(raw);
                if self.terminated {
                    self.stop_for_ever(raw);
                } else {
                    self.resume(raw, forwardable(signal));
                }
            }
            WaitStatus::PtraceSyscall(pid) => self.resume(pid.as_raw(), None),
            WaitStatus::Continued(_) | WaitStatus::StillAlive => {}
        }
    }

    /// Handles one `PTRACE_EVENT_*` stop.
    fn handle_ptrace_event(&mut self, pid: Pid, event: i32) {
        self.adopt(pid);
        if event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
            // The process is about to end. The raw wait status of the event
            // tells why. This stop comes before the process really dies, so
            // the monitor reports the end as early as possible.
            //
            // The kernel also makes this stop after SIGKILL. The process only
            // dies after the monitor lets it continue, so this arm must run
            // even when the firewall already ended the session.
            if let Ok(raw) = ptrace::getevent(NixPid::from_raw(pid)) {
                let (code, signal) = decode_status(raw as i32);
                self.note_exit(pid, code, signal);
            }
            self.resume(pid, None);
            return;
        }
        if self.terminated {
            self.stop_for_ever(pid);
            return;
        }
        if event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
            self.handle_exec(pid);
            return;
        }
        if event == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
            self.handle_seccomp(pid);
            return;
        }
        if event == ptrace::Event::PTRACE_EVENT_FORK as i32
            || event == ptrace::Event::PTRACE_EVENT_VFORK as i32
            || event == ptrace::Event::PTRACE_EVENT_CLONE as i32
        {
            if let Ok(raw_child) = ptrace::getevent(NixPid::from_raw(pid)) {
                let child = raw_child as Pid;
                // A clone that shares the address space is a thread. The task
                // then has its own identifier but the thread-group identifier
                // of its leader.
                let is_thread = event == ptrace::Event::PTRACE_EVENT_CLONE as i32
                    && procfs::is_thread(child).unwrap_or(false);
                self.note_child(pid, child, is_thread);
            }
            self.resume(pid, None);
            return;
        }
        self.resume(pid, None);
    }

    /// Holds a process at its exec stop and asks the handler what to do.
    ///
    /// The kernel stopped the process after it loaded the new program image
    /// and before the program ran one instruction. A process that the monitor
    /// kills here never runs the new program.
    fn handle_exec(&mut self, pid: Pid) {
        self.adopt(pid);

        let info = match procfs::read_process(pid, &self.config.env_allowlist) {
            Some(info) => info,
            None => {
                self.emit(
                    pid,
                    EventKind::MonitorWarning {
                        message: format!("process {pid} ended before the monitor could read it"),
                    },
                );
                let mut info = ProcessInfo::from_pid(pid);
                info.ppid = self.parents.get(&pid).copied();
                info
            }
        };

        let snapshot = if self.config.capture_input {
            Some(InputSnapshot {
                stdin: crate::inspect::stdin_snapshot(pid, self.config.max_input_bytes),
                script: crate::inspect::script_snapshot(&info, self.config.max_input_bytes),
            })
        } else {
            None
        };

        self.emit(
            pid,
            EventKind::ProcessExec {
                process: Box::new(info.clone()),
            },
        );
        self.warn_about_privilege(pid, &info);
        self.warn_about_foreign_abi(pid, &info);
        if let Some(data) = snapshot.as_ref().and_then(|snap| snap.stdin.clone()) {
            self.emit(
                pid,
                EventKind::StdinWrite {
                    stream: InputStream::Stdin,
                    data,
                },
            );
        }

        let ancestry = self.ancestry(pid);
        let answer = self.handler.on_exec(&info, &ancestry, snapshot.as_ref());
        match answer {
            Intercept::Continue => self.resume(pid, None),
            // There is no call to fail at an exec stop, so a refusal can only
            // mean the same as a denial: the program must not run.
            Intercept::Deny | Intercept::Refuse => self.kill_one(pid),
            Intercept::TerminateSession => {
                self.terminated = true;
                self.kill_tree();
            }
        }
    }

    /// Tells the user why a program that raises privilege will not work.
    ///
    /// The kernel takes the setuid bit away from any program that a normal
    /// user traces. That is true of the shipping monitor and it was true
    /// before the kernel filter existed. The filter also needs `no_new_privs`,
    /// which takes the same thing away a second time. Neither is new, but the
    /// error that `sudo` prints names none of it, so the user would blame
    /// `sudo` and not the firewall.
    fn warn_about_privilege(&mut self, pid: Pid, info: &ProcessInfo) {
        let program = info.program_name().to_string();
        if !PRIVILEGE_PROGRAMS.contains(&program.as_str()) {
            return;
        }
        self.emit(
            pid,
            EventKind::MonitorWarning {
                message: format!(
                    "{program} cannot raise the privilege of this session. The kernel takes the \
                     setuid bit away from every program that a traced session starts, so \
                     {program} fails with an error of its own that does not name the firewall. \
                     Run the command outside the firewall when you really need it."
                ),
            },
        );
    }

    /// Tells the user that the kernel filter does not watch this program.
    ///
    /// The filter holds a table of the system-call numbers of one
    /// architecture, and it lets a call of another architecture through
    /// rather than judging it with the wrong table. A 32-bit program on this
    /// 64-bit machine is exactly that case: the exec boundary still holds it,
    /// but no file open and no connection of that program reaches the
    /// firewall.
    ///
    /// The monitor says it one time for each process, and only when the
    /// session really got a filter. A session with the filter switched off
    /// already knows that it observes nothing of this kind.
    fn warn_about_foreign_abi(&mut self, pid: Pid, info: &ProcessInfo) {
        if self.filter == SyscallFilter::Off {
            return;
        }
        let Some(exe) = info.exe.as_deref() else {
            return;
        };
        if !procfs::is_elf32(std::path::Path::new(exe)) {
            return;
        }
        if !self.warned_abi.insert(pid) {
            return;
        }
        let program = info.program_name().to_string();
        self.emit(
            pid,
            EventKind::MonitorWarning {
                message: format!(
                    "{program} is a 32-bit program, and the system-call filter of this \
                     session is built for 64-bit programs. The firewall still holds every \
                     new program of this process, but it observes no file open and no \
                     connection inside it."
                ),
            },
        );
    }

    /// Holds a process at a system-call stop and asks the handler what to do.
    ///
    /// The kernel picked this call out with the filter and has not made it
    /// yet. Nothing has happened, so a refusal here is complete: no byte is
    /// written and no packet leaves.
    ///
    /// The monitor lets a call it cannot read run. It never guesses what a
    /// program is about to do.
    fn handle_seccomp(&mut self, pid: Pid) {
        let Some(action) = seccomp::observe(pid) else {
            self.resume(pid, None);
            return;
        };

        self.emit(pid, event_of(&action));

        let ancestry = self.ancestry(pid);
        match self.handler.on_syscall(pid, &action, &ancestry) {
            Intercept::Continue => {
                // The call will run, and on a path the floor denies the
                // kernel will refuse it. That refusal is certain — the
                // ruleset was fixed before the program started and can never
                // be relaxed — so the monitor explains it now, with the rule
                // class the kernel enforces. Without this, the program sees
                // a bare `EACCES` and the user blames the file.
                if let Some(plan) = self.floor.as_ref() {
                    if let Action::FileOpen { path, write } = &action {
                        if let Some(denial) = plan.denies(path, *write) {
                            self.emit(
                                pid,
                                EventKind::KernelDenied {
                                    rule: denial.rule.map(str::to_string),
                                    path: denial.path,
                                },
                            );
                        }
                    }
                }
                self.resume(pid, None);
            }
            Intercept::Refuse => {
                if let Err(error) = seccomp::refuse(pid) {
                    // The monitor could not write the registers, so it cannot
                    // let the call fail. Killing the process is the only
                    // answer left that does not let the action through.
                    self.emit(
                        pid,
                        EventKind::MonitorWarning {
                            message: format!(
                                "cannot refuse the call of process {pid} ({error}); \
                                 the firewall stops the process instead"
                            ),
                        },
                    );
                    self.kill_one(pid);
                }
                self.resume(pid, None);
            }
            Intercept::Deny => self.kill_one(pid),
            Intercept::TerminateSession => {
                self.terminated = true;
                self.kill_tree();
            }
        }
    }

    /// Adds a process that the monitor meets for the first time.
    ///
    /// A new process can stop before the fork event of its parent arrives.
    /// The monitor then reads the parent from `/proc` and gives the process
    /// the same trace options, so nothing of the tree is ever lost.
    fn adopt(&mut self, pid: Pid) {
        if pid == self.root || self.known.contains(&pid) {
            return;
        }
        self.known.insert(pid);
        self.tracked.insert(pid);
        // A child inherits the options of its parent. A process that the
        // monitor did not expect may not have them, so set them again.
        let _ = ptrace::setoptions(NixPid::from_raw(pid), TRACE_OPTIONS);

        let parent = procfs::read_stat(pid)
            .map(|stat| stat.ppid)
            .filter(|ppid| self.known.contains(ppid))
            .unwrap_or(self.root);
        let is_thread = procfs::is_thread(pid).unwrap_or(false);
        if is_thread {
            self.threads.insert(pid);
        }
        self.parents.entry(pid).or_insert(parent);
        if self.forked.insert(pid) {
            self.emit(
                parent,
                EventKind::ProcessFork {
                    child_pid: pid,
                    is_thread,
                },
            );
        }
    }

    /// Records a new child and reports it once.
    fn note_child(&mut self, parent: Pid, child: Pid, is_thread: bool) {
        self.parents.entry(child).or_insert(parent);
        if self.known.insert(child) {
            self.tracked.insert(child);
        }
        if is_thread {
            self.threads.insert(child);
        }
        if self.forked.insert(child) {
            self.emit(
                parent,
                EventKind::ProcessFork {
                    child_pid: child,
                    is_thread,
                },
            );
        }
    }

    /// Reports the end of a process exactly one time.
    ///
    /// The stop before the real end is the last chance to read the session
    /// identifier of the process from `/proc`. A daemon that called `setsid`
    /// and never ran another program carries its detachment nowhere else, so
    /// the exit event carries the value for the graph to compare.
    fn note_exit(&mut self, pid: Pid, code: Option<i32>, signal: Option<i32>) {
        if pid == self.root {
            self.root_code = code;
            self.root_signal = signal;
        }
        if self.exited.insert(pid) {
            let sid = procfs::read_stat(pid)
                .map(|stat| stat.sid)
                .filter(|sid| *sid > 0);
            self.emit(pid, EventKind::ProcessExit { code, signal, sid });
        }
    }

    /// Lets a stopped process continue and gives it a signal.
    ///
    /// The monitor only forgets a process when the process is really gone. A
    /// process that waits for its parent to read its end is still in `/proc`,
    /// so the loop keeps it and reads its end later.
    fn resume(&mut self, pid: Pid, signal: Option<Signal>) {
        match ptrace::cont(NixPid::from_raw(pid), signal) {
            Ok(()) => {}
            Err(Errno::ESRCH) => {
                if procfs::read_stat(pid).is_none() {
                    self.tracked.remove(&pid);
                }
            }
            Err(error) => {
                self.emit(
                    pid,
                    EventKind::MonitorWarning {
                        message: format!("cannot continue process {pid}: {error}"),
                    },
                );
                self.tracked.remove(&pid);
            }
        }
    }

    /// Stops one process for ever.
    fn kill_one(&mut self, pid: Pid) {
        let _ = kill(NixPid::from_raw(pid), Signal::SIGKILL);
    }

    /// Kills a process that stopped after the firewall ended the session.
    ///
    /// The process must also continue. A process that stays in a trace stop
    /// never reaches its own end, so the loop would wait for ever.
    fn stop_for_ever(&mut self, pid: Pid) {
        self.kill_one(pid);
        self.resume(pid, None);
    }

    /// Stops every process of the tree, the deepest child first.
    fn kill_tree(&mut self) {
        let mut order: Vec<Pid> = self.tracked.iter().copied().collect();
        order.sort_by_key(|pid| std::cmp::Reverse(self.depth(*pid)));
        for pid in order {
            self.kill_one(pid);
        }
    }

    /// Returns how many parents a process has inside the session.
    fn depth(&self, pid: Pid) -> usize {
        self.ancestry(pid).len()
    }

    /// Returns the ancestry of a process, the nearest parent first.
    fn ancestry(&self, pid: Pid) -> Vec<Pid> {
        let mut chain = Vec::new();
        let mut current = pid;
        while let Some(parent) = self.parents.get(&current).copied() {
            chain.push(parent);
            current = parent;
            if chain.len() >= MAX_ANCESTRY {
                break;
            }
        }
        chain
    }

    /// Sends one normalized event to the handler.
    ///
    /// The sequence number stays at zero. The event sink of the recorder owns
    /// the numbering, so a replayed trace keeps one single order.
    fn emit(&mut self, pid: Pid, kind: EventKind) {
        let event = Event::new(self.session.session_id.clone(), pid, kind);
        self.handler.on_event(event);
    }

    /// Returns the result of the session.
    fn outcome(&self) -> SessionOutcome {
        SessionOutcome {
            exit_code: self.root_code,
            signal: self.root_signal,
            terminated_by_firewall: self.terminated,
            process_count: self.known.len().saturating_sub(self.threads.len()),
        }
    }
}

/// Waits for one state change and repeats the call after an interrupt.
///
/// Returns `Ok(None)` when the monitor has no child left.
fn wait_any(pid: Option<NixPid>) -> Result<Option<WaitStatus>> {
    loop {
        match waitpid(pid, Some(WaitPidFlag::__WALL)) {
            Ok(status) => return Ok(Some(status)),
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => return Ok(None),
            Err(error) => return Err(Error::os(format!("waitpid failed: {error}"))),
        }
    }
}

/// Makes the pipe through which the child reports the fate of the floor.
///
/// Both ends close themselves at `execve`, because a descriptor that the
/// child never needed would leak into every program of the session.
fn report_pipe() -> Result<(std::fs::File, std::fs::File)> {
    use std::os::unix::io::FromRawFd;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` writes two descriptors into `fds` and touches nothing
    // else.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if rc != 0 {
        return Err(Error::os(format!(
            "pipe2 failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both descriptors are fresh and owned from here on.
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    })
}

/// Returns the signal that the monitor gives back to a stopped process.
///
/// A group stop uses the same wait status as a normal signal. Without
/// `PTRACE_SEIZE` the monitor cannot separate the two cases, so it lets the
/// process continue with no signal. This keeps the tree alive. The cost is
/// that a real job-control stop of the tree does not work while the monitor
/// runs, which is a safe simplification for a coding-agent session.
///
/// `SIGTRAP` never goes back, because the kernel and not the program made it.
fn forwardable(signal: Signal) -> Option<Signal> {
    match signal {
        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU | Signal::SIGTRAP => {
            None
        }
        other => Some(other),
    }
}

/// Makes the event that reports one held system call.
fn event_of(action: &Action) -> EventKind {
    match action {
        Action::FileOpen { path, write } => EventKind::FileOpen {
            path: path.clone(),
            write: *write,
        },
        Action::NetworkConnect { addr, port, host } => EventKind::NetworkConnect {
            addr: addr.clone(),
            port: *port,
            host: host.clone(),
        },
        // `seccomp::observe` makes no other shape. A future call would have
        // to bring its own event, and until then the monitor says what it saw
        // rather than reporting the wrong kind.
        other => EventKind::MonitorWarning {
            message: format!("the monitor has no event for a {} action", other.kind()),
        },
    }
}

/// Reads an exit code and a signal from a raw wait status.
fn decode_status(raw: i32) -> (Option<i32>, Option<i32>) {
    if libc::WIFEXITED(raw) {
        (Some(libc::WEXITSTATUS(raw)), None)
    } else if libc::WIFSIGNALED(raw) {
        (None, Some(libc::WTERMSIG(raw)))
    } else {
        (None, None)
    }
}
