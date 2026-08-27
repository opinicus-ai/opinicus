//! The `ptrace` event loop that follows a whole process tree.
//!
//! The loop launches one command, follows every descendant, and holds each
//! process at the moment the kernel loaded a new program but did not yet run
//! one instruction of it. That moment is the point where the firewall can
//! still stop a dangerous program.

use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid as NixPid;

use af_core::{Error, Event, EventKind, InputStream, Pid, ProcessInfo, Result, SessionMeta};

use crate::{procfs, InputSnapshot, Intercept, MonitorConfig, MonitorHandler, SessionOutcome};

/// Trace options that the monitor uses for every process of the tree.
///
/// `PTRACE_O_EXITKILL` is important for safety. It tells the kernel to kill
/// every traced process when the monitor dies, so no process of the tree ever
/// stays stopped without a monitor.
pub const TRACE_OPTIONS: ptrace::Options = ptrace::Options::PTRACE_O_TRACEFORK
    .union(ptrace::Options::PTRACE_O_TRACEVFORK)
    .union(ptrace::Options::PTRACE_O_TRACECLONE)
    .union(ptrace::Options::PTRACE_O_TRACEEXEC)
    .union(ptrace::Options::PTRACE_O_TRACEEXIT)
    .union(ptrace::Options::PTRACE_O_EXITKILL);

/// Highest depth that the ancestry walk accepts.
///
/// The parent map can never hold a cycle, but a guard keeps the monitor safe
/// against damaged data.
const MAX_ANCESTRY: usize = 256;

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
    terminated: bool,
    root_code: Option<i32>,
    root_signal: Option<i32>,
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
    // SAFETY: the closure only calls ptrace, which is safe in a forked child.
    unsafe {
        command.pre_exec(|| ptrace::traceme().map_err(std::io::Error::from));
    }

    let child = command.spawn().map_err(|error| {
        let shown = af_core::display::truncate(&config.command.join(" "), 120);
        Error::monitor(format!("cannot start {shown}: {error}"))
    })?;
    let root = child.id() as Pid;

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
        terminated: false,
        root_code: None,
        root_signal: None,
    };

    tracer.run_loop()?;
    Ok(tracer.outcome())
}

impl Tracer<'_> {
    /// Waits for the first stop of the root and then follows the whole tree.
    fn run_loop(&mut self) -> Result<()> {
        if !self.await_root_start()? {
            return Ok(());
        }
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
    fn note_exit(&mut self, pid: Pid, code: Option<i32>, signal: Option<i32>) {
        if pid == self.root {
            self.root_code = code;
            self.root_signal = signal;
        }
        if self.exited.insert(pid) {
            self.emit(pid, EventKind::ProcessExit { code, signal });
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
