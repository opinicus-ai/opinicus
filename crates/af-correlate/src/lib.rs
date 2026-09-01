//! The correlation engine: expected view versus observed view.
//!
//! The direction of record (`docs/DIRECTION.md` §3.4) asks for one thing:
//! when the in-process sensor and the external monitor disagree, the
//! disagreement is a signal of its own. This crate computes the
//! disagreement.
//!
//! * **Expected** — the sensor trace and the registration record of the
//!   in-process sensor ([`RegLine`]): what the instances the firewall
//!   installed said they were doing.
//! * **Observed** — the product trace: what the monitor's own sensors saw.
//!
//! The engine reports. It never decides: the disagreement becomes an
//! [`af_core::DiscrepancyKind`] fact, and the rules of the policy engine
//! judge it like any other action. The decision log binds the keying: every
//! check names the sensor instances the firewall itself installed, so a
//! static binary and a raw `syscall()` — which never touch a preload — can
//! never raise a fact here.

use std::collections::HashMap;
use std::path::Path;

use af_core::{Decision, DiscrepancyKind, Event, EventKind, Pid, TimestampNanos};
use serde::Deserialize;

/// One line of the registration record of the in-process sensor.
///
/// The record is append-only and one line per raw write, so it survives the
/// death of the writing process. It is not an `af-core` event: the sensor
/// writes it before it can know anything about the schema, so the engine
/// reads it with its own small reader here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegLine {
    /// `sensor_register`, `sensor_heartbeat` or `sensor_exit`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Identifier of the instance, unique per process image.
    pub instance: String,
    /// Process identifier the instance lives in.
    pub pid: Pid,
    /// Parent of the process, as the sensor read it.
    #[serde(default)]
    pub ppid: Pid,
    /// Program of the process, as the sensor read it.
    #[serde(default)]
    pub exe: String,
    /// Session identifier the sensor carried.
    #[serde(default)]
    pub session: String,
    /// Time of the line, in nanoseconds after the Unix epoch.
    pub ts: TimestampNanos,
}

/// Reads a registration record. A line that is not from the sensor is
/// skipped, never fatal: the record is the evidence, and one torn line must
/// not hide the rest.
pub fn read_reg(path: &Path) -> std::io::Result<Vec<RegLine>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// How the engine tunes its checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// How long an instance that proved it talks may stay quiet before the
    /// engine asks the external view whether its process still lives.
    ///
    /// The default of 3000 ms is the value the M2 spike measured: the
    /// positive control fires at about 5 s of quiet while the benign corpus
    /// produces none.
    pub stale_ms: u64,
    /// Compares write-intent file opens as well as connections.
    ///
    /// Off by default, on the measurement of the M5 gate: a write open of a
    /// normal tool reaches the external view through paths the preload
    /// cannot see — `mkstemp` and other glibc-internal opens, retried lock
    /// attempts, reflog re-opens — and the comparison fired 30 times on a
    /// 28-second corpus session against 3 seeded attacks
    /// (`research/bypass/correlate.sh`, `--compare-write-opens`). The
    /// comparison stays available as research telemetry; the product
    /// compares connections, which the corpus exercises through libc or
    /// not at all.
    pub compare_write_opens: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stale_ms: 3000,
            compare_write_opens: false,
        }
    }
}

/// One disagreement the engine found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which way the views disagree.
    pub kind: DiscrepancyKind,
    /// The process the disagreement is about.
    pub pid: Pid,
    /// Time of the fact that proves the disagreement.
    pub ts: TimestampNanos,
    /// The measured evidence, one line.
    pub detail: String,
}

/// What the engine measured on the way, so a report can name its own basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Sensor instances the record names.
    pub instances: usize,
    /// Execs the external view reported.
    pub external_execs: usize,
    /// Exec intents the sensor reported.
    pub sensor_intents: usize,
    /// Held file opens and connects the external view reported.
    pub external_actions: usize,
    /// Disagreements of every kind.
    pub findings: usize,
}

/// The answer of the correlation: every disagreement, with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The findings, in the order of their proving events.
    pub findings: Vec<Finding>,
    /// What the engine measured on the way.
    pub counts: Counts,
}

/// Compares the two views of one session.
///
/// `product` is the trace the monitor wrote, `sensor` the trace of the
/// in-process sensor, and `reg` the registration record that names the
/// instances the firewall installed. Every check keys on that record: an
/// empty record means no sensor was installed, and then no disagreement can
/// exist — which is the quiet, correct answer for a session without the
/// sensor.
pub fn correlate(product: &[Event], sensor: &[Event], reg: &[RegLine], opts: &Options) -> Report {
    let mut engine = Engine::new(product, sensor, reg, opts);
    engine.run();
    Report {
        findings: engine.findings,
        counts: engine.counts,
    }
}

/// The engine holds the indexes of both views and the findings it raised.
struct Engine<'a> {
    product: &'a [Event],
    sensor: &'a [Event],
    reg: &'a [RegLine],
    opts: &'a Options,
    /// Maps a thread identifier to the leader of its thread group.
    ///
    /// The sensor reports every event under the group identifier, because it
    /// reads `getpid`. The external view reports a syscall under the
    /// identifier of the thread that made it. Node and Python run real
    /// threads that open files, so without this map the engine would read a
    /// normal thread pool as an unreported action.
    leader: HashMap<Pid, Pid>,
    /// Per process: the sensor's state, aggregated over its instances.
    sensor_state: HashMap<Pid, SensorState>,
    /// Every exec the external view saw: `(pid, ts, dynamic, carried)`.
    execs: Vec<ExecView>,
    /// Every held file open and connect of the external view.
    actions: Vec<ActionView>,
    /// Times of every external event, keyed on the group leader, for the
    /// liveness question of the silent-sensor check.
    external_times: Vec<(Pid, TimestampNanos)>,
    /// Sensor exec intents, for the reported-not-seen check.
    intents: Vec<(Pid, TimestampNanos)>,
    /// Registration times per process, for the plumbing windows.
    registers: Vec<(Pid, TimestampNanos)>,
    /// The windows in which a write open of a process is the sensor's own
    /// plumbing, not the program acting.
    ///
    /// One window starts at each exec stop: the dynamic linker and the
    /// sensor's constructor open with raw system calls — the loader opens
    /// the program and its libraries, the constructor opens the trace and
    /// the record — and none of that crosses the interposed libc. The
    /// window ends at the first registration of the successor image, which
    /// is the moment the sensor is armed and the program proper begins. An
    /// exec with no following registration is an image that never armed:
    /// the window stays open, and `dark_since` says the same thing for the
    /// rest of the checks.
    plumbing: Vec<(Pid, Option<TimestampNanos>, TimestampNanos)>,
    /// Sensor opens and connects, as multisets the match consumes.
    sensor_opens: HashMap<(Pid, String, bool), usize>,
    sensor_connects: HashMap<(Pid, String, u16), usize>,
    findings: Vec<Finding>,
    counts: Counts,
}

/// The sensor's own state for one process, aggregated over its instances.
#[derive(Debug, Default, Clone)]
struct SensorState {
    /// Latest line of the record for this process.
    last_reg: Option<TimestampNanos>,
    /// The record holds a heartbeat of this process.
    ///
    /// A heartbeat proves the heartbeat thread exists. An instance that
    /// never beat can be a forked child without the thread — the thread does
    /// not survive a fork — and such an instance is quiet, not silent.
    has_beat: bool,
    /// Every word the sensor said about this process, from the record and
    /// from the trace, in order.
    ///
    /// A healthy instance talks at about 1 Hz — the heartbeat thread fills
    /// every idle second — so the words of a live, armed instance are dense.
    /// A gap wider than the quiet window, with the external view proving the
    /// process alive inside it, is the silence this engine reports.
    words: Vec<TimestampNanos>,
    /// The last event the sensor trace holds for this process, and whether
    /// it was an exec intent. An intent as the last word means the image was
    /// replaced: the instance died with the old image, and the new image
    /// never promised a sensor. A static program there is the normal case
    /// the decision log protects.
    last_event: Option<(TimestampNanos, bool)>,
}

/// One exec of the external view.
#[derive(Debug, Clone)]
struct ExecView {
    pid: Pid,
    ts: TimestampNanos,
    exe: Option<String>,
    /// Whether the program file needs the dynamic linker.
    dynamic: Option<bool>,
    /// Whether the environment of the exec carries a preload value.
    preload: Option<String>,
}

/// One held action of the external view.
#[derive(Debug, Clone)]
enum ActionView {
    Open {
        pid: Pid,
        ts: TimestampNanos,
        path: String,
        write: bool,
    },
    Connect {
        pid: Pid,
        ts: TimestampNanos,
        addr: String,
        port: u16,
    },
}

impl<'a> Engine<'a> {
    fn new(
        product: &'a [Event],
        sensor: &'a [Event],
        reg: &'a [RegLine],
        opts: &'a Options,
    ) -> Self {
        let mut engine = Engine {
            product,
            sensor,
            reg,
            opts,
            leader: HashMap::new(),
            sensor_state: HashMap::new(),
            execs: Vec::new(),
            actions: Vec::new(),
            external_times: Vec::new(),
            intents: Vec::new(),
            registers: Vec::new(),
            plumbing: Vec::new(),
            sensor_opens: HashMap::new(),
            sensor_connects: HashMap::new(),
            findings: Vec::new(),
            counts: Counts::default(),
        };
        engine.index();
        engine
    }

    /// Builds the indexes of both views.
    fn index(&mut self) {
        // The thread map: a fork event with `is_thread` names a task of the
        // parent's group. The leader of a thread is the leader of its
        // parent, which resolves chains of thread creations.
        let mut parent_of: HashMap<Pid, (Pid, bool)> = HashMap::new();
        for event in self.product {
            if let EventKind::ProcessFork {
                child_pid,
                is_thread,
            } = &event.kind
            {
                parent_of.insert(*child_pid, (event.pid, *is_thread));
            }
        }
        fn leader_of(map: &HashMap<Pid, (Pid, bool)>, pid: Pid) -> Pid {
            let mut current = pid;
            let mut steps = 0;
            while let Some(&(parent, is_thread)) = map.get(&current) {
                if !is_thread {
                    break;
                }
                current = parent;
                steps += 1;
                if steps > 128 {
                    break;
                }
            }
            current
        }
        for &child in parent_of.keys() {
            self.leader.insert(child, leader_of(&parent_of, child));
        }

        // The sensor's own state, per process.
        self.counts.instances = self.reg.len();
        for line in self.reg {
            let state = self.sensor_state.entry(line.pid).or_default();
            match line.kind.as_str() {
                "sensor_register" | "sensor_heartbeat" | "sensor_exit" => {}
                _ => continue,
            }
            if line.kind == "sensor_heartbeat" {
                state.has_beat = true;
            }
            if line.kind == "sensor_register" {
                self.registers.push((line.pid, line.ts));
            }
            state.words.push(line.ts);
            state.last_reg = Some(
                state
                    .last_reg
                    .map_or(line.ts, |ts: TimestampNanos| ts.max(line.ts)),
            );
        }
        for event in self.sensor {
            let is_intent = matches!(event.kind, EventKind::ProcessExec { .. });
            let state = self.sensor_state.entry(event.pid).or_default();
            let better = state.last_event.is_none_or(|(ts, _)| event.ts >= ts);
            if better {
                state.last_event = Some((event.ts, is_intent));
            }
            state.words.push(event.ts);
            match &event.kind {
                EventKind::ProcessExec { .. } => self.intents.push((event.pid, event.ts)),
                EventKind::FileOpen { path, write } => {
                    *self
                        .sensor_opens
                        .entry((event.pid, path.clone(), *write))
                        .or_insert(0) += 1;
                }
                EventKind::NetworkConnect { addr, port, .. } => {
                    *self
                        .sensor_connects
                        .entry((event.pid, addr.clone(), *port))
                        .or_insert(0) += 1;
                }
                _ => {}
            }
        }

        // The external view: execs, held actions and liveness times. A call
        // the kernel refused or the policy rejected never ran, so the sensor
        // is honest when it reports nothing for it; both exclusions come
        // from the trace itself.
        let mut denied: Vec<(Pid, String)> = Vec::new();
        let mut refused: Vec<(Pid, ActionKey)> = Vec::new();
        for event in self.product {
            match &event.kind {
                EventKind::KernelDenied { path, .. } => denied.push((event.pid, path.clone())),
                EventKind::PolicyDecision {
                    action, verdict, ..
                } => {
                    // A call the policy refused never ran, and the sensor is
                    // honest when it reports nothing for it.
                    if let Some(key) = (verdict.decision != Decision::Allow)
                        .then(|| ActionKey::of(action))
                        .flatten()
                    {
                        refused.push((event.pid, key));
                    }
                }
                _ => {}
            }
        }
        for event in self.product {
            let group = self.group(event.pid);
            self.external_times.push((group, event.ts));
            match &event.kind {
                EventKind::ProcessExec { process } => {
                    self.counts.external_execs += 1;
                    self.execs.push(ExecView {
                        pid: event.pid,
                        ts: event.ts,
                        exe: process.exe.clone(),
                        dynamic: process.dynamic_link,
                        preload: process.env.get("LD_PRELOAD").cloned(),
                    });
                }
                EventKind::FileOpen { path, write } => {
                    self.counts.external_actions += 1;
                    // The product posture compares connections only. A read
                    // open is what the loader machinery of a normal session
                    // makes between the program and its libraries, and the
                    // M2 sensor hooks none of it on purpose; a rule that
                    // compared reads would fire on every dynamic exec and
                    // every dlopen. A write open proved just as noisy on
                    // the benign corpus — 30 firings on one session — so it
                    // lives behind `compare_write_opens` for research.
                    if !write || !self.opts.compare_write_opens {
                        continue;
                    }
                    let key = ActionKey::Path(path.clone());
                    if denied.contains(&(event.pid, path.clone()))
                        || refused.contains(&(event.pid, key))
                    {
                        continue;
                    }
                    self.actions.push(ActionView::Open {
                        pid: event.pid,
                        ts: event.ts,
                        path: path.clone(),
                        write: *write,
                    });
                }
                EventKind::NetworkConnect { addr, port, .. } => {
                    self.counts.external_actions += 1;
                    let key = ActionKey::Endpoint(addr.clone(), *port);
                    if refused.contains(&(event.pid, key)) {
                        continue;
                    }
                    self.actions.push(ActionView::Connect {
                        pid: event.pid,
                        ts: event.ts,
                        addr: addr.clone(),
                        port: *port,
                    });
                }
                _ => {}
            }
        }
        for state in self.sensor_state.values_mut() {
            state.words.sort_unstable();
            state.words.dedup();
        }
        self.external_times.sort_unstable();
        self.counts.sensor_intents = self.intents.len();

        // The plumbing windows, from the exec stops and the registrations
        // that follow them.
        for exec in &self.execs {
            let next_register = self
                .registers
                .iter()
                .map(|&(pid, ts)| (pid, ts))
                .filter(|&(pid, ts)| pid == exec.pid && ts > exec.ts)
                .map(|(_, ts)| ts)
                .min();
            self.plumbing.push((exec.pid, next_register, exec.ts));
        }
    }

    /// The group leader of a process: itself, or the leader of its thread
    /// group when the trace named it as a thread.
    fn group(&self, pid: Pid) -> Pid {
        self.leader.get(&pid).copied().unwrap_or(pid)
    }

    /// The time after which the sensor of a process owes nothing: the time
    /// of its last word, when its last word was an exec intent. The image
    /// was replaced, and the new image decides whether a sensor exists.
    fn dark_since(&self, pid: Pid) -> Option<TimestampNanos> {
        let state = self.sensor_state.get(&pid)?;
        let (event_ts, is_intent) = state.last_event?;
        if !is_intent {
            return None;
        }
        // A record line after the intent — a heartbeat, an exit, the
        // registration of a new image — proves the sensor outlived the
        // intent, so the intent was a failed exec and the process went on.
        if state.last_reg.is_some_and(|reg| reg > event_ts) {
            return None;
        }
        Some(event_ts)
    }

    /// Returns true when a moment of a process falls in a plumbing window.
    fn in_plumbing(&self, pid: Pid, ts: TimestampNanos) -> bool {
        self.plumbing
            .iter()
            .any(|&(p, end, start)| pid == p && ts > start && end.is_none_or(|end| ts < end))
    }

    fn run(&mut self) {
        self.silent_sensors();
        self.contradicted_actions();
        self.spawn_seen_unreported();
        self.spawn_reported_unseen();
        self.findings.sort_by_key(|f| (f.ts, f.pid));
        self.counts.findings = self.findings.len();
    }

    /// A sensor instance the firewall installed went quiet while its process
    /// lived on.
    ///
    /// A healthy instance is dense: the heartbeat thread fills every idle
    /// second at about 1 Hz, and a busy instance talks more, not less. So
    /// the engine reads the words of every instance that proved it carries
    /// the thread (a heartbeat) and looks for one gap wider than the quiet
    /// window — with the external view proving the process alive inside the
    /// gap, because a dead process owes no words. An instance that never
    /// beat can be a forked child without the thread, and a gap that starts
    /// at an exec intent as the last word is an image replacement — a static
    /// successor is the everyday case, and M4 owns the stripped-preload one.
    fn silent_sensors(&mut self) {
        let window = self.opts.stale_ms as i128 * 1_000_000;
        let mut findings = std::mem::take(&mut self.findings);
        for (&pid, state) in &self.sensor_state {
            if !state.has_beat || state.words.len() < 2 {
                continue;
            }
            let dark = self.dark_since(pid);
            for pair in state.words.windows(2) {
                let (start, end) = (pair[0], pair[1]);
                self.quiet_gap(pid, start, Some(end), dark, window, &mut findings);
            }
            // The trailing gap: no next word, so the proof is any external
            // event past the window after the last word.
            if let Some(&last) = state.words.last() {
                if dark != Some(last) {
                    self.quiet_gap(pid, last, None, dark, window, &mut findings);
                }
            }
        }
        self.findings = findings;
    }

    /// Reads one quiet gap of one instance and records the finding when the
    /// external view proves the process alive inside it.
    ///
    /// `end` is `None` for the trailing gap, where every later external
    /// event of the process counts as proof.
    fn quiet_gap(
        &self,
        pid: Pid,
        start: TimestampNanos,
        end: Option<TimestampNanos>,
        dark: Option<TimestampNanos>,
        window: i128,
        findings: &mut Vec<Finding>,
    ) {
        let end_bound = end.map_or(i128::MAX, |end| end as i128);
        if end_bound - start as i128 <= window {
            return;
        }
        // The gap that starts at the last word of a replaced image is the
        // successor's business, not silence.
        if dark == Some(start) {
            return;
        }
        // The external view proves the process alive inside the gap: any
        // event of the process — or of a thread of it — after the quiet
        // window and before the next word.
        let alive = self.external_times.iter().find(|&&(group, ts)| {
            group == pid && ts as i128 > start as i128 + window && (ts as i128) <= end_bound
        });
        if let Some((_, ts)) = alive {
            let quiet_ms = (*ts as i128 - start as i128) / 1_000_000;
            findings.push(Finding {
                kind: DiscrepancyKind::SensorSilentSubtree,
                pid,
                ts: *ts,
                detail: format!(
                    "instance of pid {pid} proved it talks, then said nothing for \
                     {quiet_ms} ms while the external view shows the process alive"
                ),
            });
        }
    }

    /// The external view held an action of a process that carries a
    /// registered sensor instance, and the sensor reported no such action.
    ///
    /// A held open or connect crossed the process without crossing libc,
    /// which is the shape of a sensor whose hooks are gone or whose output
    /// is cut while it keeps beating. A call the kernel or the policy
    /// refused never ran, a process with no instance never owed a report —
    /// a static binary is that case — and a process whose sensor died with
    /// a replaced image owes nothing after the replacement.
    fn contradicted_actions(&mut self) {
        let mut findings = std::mem::take(&mut self.findings);
        for action in self.actions.clone() {
            match action {
                ActionView::Open {
                    pid,
                    ts,
                    path,
                    write,
                } => {
                    let group = self.group(pid);
                    if !self.sensor_state.contains_key(&group) {
                        continue;
                    }
                    if self.dark_since(group).is_some_and(|dark| ts > dark) {
                        continue;
                    }
                    if self.in_plumbing(pid, ts) {
                        continue;
                    }
                    let key = (group, path.clone(), write);
                    let left = self.sensor_opens.get_mut(&key).filter(|n| **n > 0);
                    match left {
                        Some(n) => *n -= 1,
                        None => findings.push(Finding {
                            kind: DiscrepancyKind::ActionContradicted,
                            pid,
                            ts,
                            detail: format!(
                                "external view held open {path} for {} at pid {pid}; its \
                                 registered sensor instance reported no such open",
                                if write { "write" } else { "read" }
                            ),
                        }),
                    }
                }
                ActionView::Connect {
                    pid,
                    ts,
                    addr,
                    port,
                } => {
                    let group = self.group(pid);
                    if !self.sensor_state.contains_key(&group) {
                        continue;
                    }
                    if self.dark_since(group).is_some_and(|dark| ts > dark) {
                        continue;
                    }
                    let key = (group, addr.clone(), port);
                    let left = self.sensor_connects.get_mut(&key).filter(|n| **n > 0);
                    match left {
                        Some(n) => *n -= 1,
                        None => findings.push(Finding {
                            kind: DiscrepancyKind::ActionContradicted,
                            pid,
                            ts,
                            detail: format!(
                                "external view held connect to {addr}:{port} at pid {pid}; \
                                 its registered sensor instance reported no such connect"
                            ),
                        }),
                    }
                }
            }
        }
        self.findings = findings;
    }

    /// The external view saw a spawn that the sensor never reported.
    ///
    /// The fact keys on the environment the child inherited and on the
    /// program file itself: a child whose environment carries the session's
    /// sensor preload and whose program needs the dynamic linker must load
    /// the sensor, and the load shows — the constructor of the new image
    /// registers a fresh instance after the exec stop. A fork of a preloaded
    /// parent also registers, but *before* the exec: the engine asks for a
    /// registration at or after the exec event, which only the successor
    /// image can write. A static child (`dynamic` false) can never load a
    /// preload, a child with the preload stripped from its environment is
    /// the tamper fact of M4, and a child that registered after its exec —
    /// `posix_spawn` does, without an intent — is quiet.
    fn spawn_seen_unreported(&mut self) {
        if self.reg.is_empty() {
            return;
        }
        // What the session's own preload names: the value the launcher
        // recorded at session start. Without that fact the engine accepts
        // any preload value, because the record proves a sensor was
        // installed even when the metadata is missing.
        let session_preload = self
            .product
            .iter()
            .find_map(|event| match &event.kind {
                EventKind::SessionStart { meta, .. } => {
                    meta.sensor.as_ref().map(|sensor| sensor.preload.clone())
                }
                _ => None,
            })
            .unwrap_or_default();
        let session_parts: Vec<String> = session_preload
            .split(':')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();

        let mut findings = std::mem::take(&mut self.findings);
        for exec in self.execs.clone() {
            let Some(preload) = exec.preload.as_deref() else {
                continue;
            };
            let carried = session_parts.is_empty()
                || preload
                    .split(':')
                    .any(|part| session_parts.iter().any(|want| want == part));
            if !carried || exec.dynamic != Some(true) {
                continue;
            }
            // Only the successor image can write a registration at or after
            // its own exec stop: the exec event is written after the kernel
            // loaded the image, and a fork of a preloaded parent registers
            // before the call, never after the stop.
            let registered_after = self.reg.iter().any(|line| {
                line.kind == "sensor_register" && line.pid == exec.pid && line.ts >= exec.ts
            });
            if registered_after {
                continue;
            }
            let exe = exec.exe.as_deref().unwrap_or("an unknown program");
            findings.push(Finding {
                kind: DiscrepancyKind::SpawnSeenUnreported,
                pid: exec.pid,
                ts: exec.ts,
                detail: format!(
                    "exec of {exe} at pid {} carries the sensor preload of this session and \
                     needs the dynamic linker, and no sensor instance of the new image ever \
                     registered",
                    exec.pid
                ),
            });
        }
        self.findings = findings;
    }

    /// The sensor reported a spawn whose exec the external view never saw.
    ///
    /// In a launch session the exec stop is a kernel guarantee for the whole
    /// tree — the M1 matrix measured that nothing of the tree escapes the
    /// tracer — so this check measures the kind and expects zero. It exists
    /// because the schema promises it and because a future attach mode will
    /// not carry the guarantee. A failed exec is the normal shape of a
    /// reported spawn with no observed one: the shell keeps running and its
    /// instance keeps talking, which the `last word` test below recognizes.
    fn spawn_reported_unseen(&mut self) {
        let window = self.opts.stale_ms as i128 * 1_000_000;
        let external_execs: Vec<Pid> = self.execs.iter().map(|exec| exec.pid).collect();
        let mut findings = std::mem::take(&mut self.findings);
        for (pid, ts) in self.intents.clone() {
            if external_execs.contains(&pid) {
                continue;
            }
            // The sensor spoke again after the intent: the exec failed, the
            // image lived on. Quiet.
            if self.sensor_state.get(&pid).is_some_and(|state| {
                state.last_event.is_some_and(|(last, _)| last > ts)
                    || state.last_reg.is_some_and(|reg| reg > ts)
            }) {
                continue;
            }
            // The external view never saw the exec, the sensor never spoke
            // again, and the process lived past the window: only now is the
            // absence of the exec an absence and not a failure.
            let alive = self
                .external_times
                .iter()
                .find(|&&(group, at)| group == pid && at as i128 > ts as i128 + window);
            if let Some((_, at)) = alive {
                findings.push(Finding {
                    kind: DiscrepancyKind::SpawnReportedUnseen,
                    pid,
                    ts: *at,
                    detail: format!(
                        "sensor reported an exec of pid {pid} that the external view never \
                         saw, while the process lived on for the whole quiet window"
                    ),
                });
            }
        }
        self.findings = findings;
    }
}

/// The identity of one action, for the refusal exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionKey {
    Path(String),
    Endpoint(String, u16),
}

impl ActionKey {
    fn of(action: &af_core::Action) -> Option<Self> {
        match action {
            af_core::Action::FileOpen { path, .. } => Some(ActionKey::Path(path.clone())),
            af_core::Action::NetworkConnect { addr, port, .. } => {
                Some(ActionKey::Endpoint(addr.clone(), *port))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use af_core::{Event, EventKind, ProcessInfo, SessionMeta};

    /// Makes one product event of the external view.
    fn product(ts: u64, pid: Pid, kind: EventKind) -> Event {
        Event {
            seq: 0,
            ts,
            session_id: af_core::SessionId::from("afw-test"),
            pid,
            agent: None,
            kind,
        }
    }

    /// Makes one sensor event of the expected view.
    fn sensor(ts: u64, pid: Pid, kind: EventKind) -> Event {
        Event {
            seq: 0,
            ts,
            session_id: af_core::SessionId::from("afw-test"),
            pid,
            agent: None,
            kind,
        }
    }

    fn reg_line(kind: &str, pid: Pid, ts: u64) -> RegLine {
        RegLine {
            kind: kind.to_string(),
            instance: format!("i-{ts}-{pid}"),
            pid,
            ppid: 1,
            exe: "/tmp/payload".to_string(),
            session: "afw-test".to_string(),
            ts,
        }
    }

    /// A session start that carries the sensor of the research spike.
    fn session_with_sensor(preload: &str) -> Event {
        let mut meta = SessionMeta::new(vec!["payload".to_string()], "/tmp".to_string());
        meta.sensor = Some(af_core::SensorMeta {
            preload: preload.to_string(),
            instances: vec![10],
            trace: None,
            registration: None,
        });
        product(
            0,
            1,
            EventKind::SessionStart {
                meta: Box::new(meta),
                capabilities: vec![],
            },
        )
    }

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn an_empty_record_means_no_sensor_and_no_findings() {
        let report = correlate(
            &[session_with_sensor("/sensor.so")],
            &[],
            &[],
            &Options::default(),
        );
        assert_eq!(report.findings, Vec::<Finding>::new());
        assert_eq!(report.counts.instances, 0);
    }

    #[test]
    fn a_frozen_sensor_inside_a_living_process_is_silent() {
        // The instance registers, beats (so the thread existed), then the
        // process freezes; the external view shows it alive past the window.
        let product_trace = vec![
            product(
                0,
                1,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            product(
                10 * SECOND,
                10,
                EventKind::ProcessExit {
                    code: Some(0),
                    signal: None,
                    sid: None,
                },
            ),
        ];
        let reg = vec![
            reg_line("sensor_register", 10, 0),
            reg_line("sensor_heartbeat", 10, 2 * SECOND),
        ];
        let report = correlate(&product_trace, &[], &reg, &Options::default());
        assert_eq!(report.counts.findings, 1);
        assert_eq!(
            report.findings[0].kind,
            DiscrepancyKind::SensorSilentSubtree
        );
        assert_eq!(report.findings[0].pid, 10);
    }

    #[test]
    fn teardown_and_quiet_instances_and_failed_execs_are_not_silence() {
        let base = vec![product(
            0,
            1,
            EventKind::ProcessExec {
                process: Box::new(ProcessInfo::from_pid(10)),
            },
        )];
        // A process that ended: normal teardown. A healthy instance beats
        // about once a second while it lives, so its words are dense and no
        // gap ever crosses the window.
        let reg_exit = vec![
            reg_line("sensor_register", 10, 0),
            reg_line("sensor_heartbeat", 10, 2 * SECOND),
            reg_line("sensor_heartbeat", 10, 3 * SECOND),
            reg_line("sensor_heartbeat", 10, 4 * SECOND),
            reg_line("sensor_heartbeat", 10, 5 * SECOND),
            reg_line("sensor_exit", 10, 6 * SECOND),
        ];
        let report = correlate(
            &{
                let mut trace = base.clone();
                trace.push(product(
                    6 * SECOND,
                    10,
                    EventKind::ProcessExit {
                        code: Some(0),
                        signal: None,
                        sid: None,
                    },
                ));
                trace
            },
            &[],
            &reg_exit,
            &Options::default(),
        );
        assert_eq!(report.counts.findings, 0, "an exited instance is teardown");

        // An instance that never beat: a forked child has no thread, and
        // such an instance is quiet, not silent.
        let reg_quiet = vec![reg_line("sensor_register", 10, 0)];
        let report = correlate(
            &{
                let mut trace = base.clone();
                trace.push(product(
                    10 * SECOND,
                    10,
                    EventKind::ProcessExit {
                        code: Some(0),
                        signal: None,
                        sid: None,
                    },
                ));
                trace
            },
            &[],
            &reg_quiet,
            &Options::default(),
        );
        assert_eq!(
            report.counts.findings, 0,
            "an instance without a heartbeat never promised one"
        );

        // The process died inside the window: nothing proves it lived on.
        let reg_short = vec![
            reg_line("sensor_register", 10, 0),
            reg_line("sensor_heartbeat", 10, 2 * SECOND),
        ];
        let report = correlate(
            &{
                let mut trace = base.clone();
                trace.push(product(
                    3 * SECOND,
                    10,
                    EventKind::ProcessExit {
                        code: Some(0),
                        signal: None,
                        sid: None,
                    },
                ));
                trace
            },
            &[],
            &reg_short,
            &Options::default(),
        );
        assert_eq!(
            report.counts.findings, 0,
            "the quiet window was never crossed"
        );
    }

    #[test]
    fn a_sensor_whose_last_word_was_an_exec_intent_died_with_its_image() {
        // A beating process whose final sensor word is an exec intent: the
        // image was replaced, and a static successor is the normal case.
        let product_trace = vec![
            product(
                0,
                1,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            // The exec stop is a kernel guarantee: the external view sees the
            // replacement even when the successor never loads the sensor.
            product(
                5 * SECOND,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            product(
                10 * SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/x".to_string(),
                    write: true,
                },
            ),
            product(
                11 * SECOND,
                10,
                EventKind::ProcessExit {
                    code: Some(0),
                    signal: None,
                    sid: None,
                },
            ),
        ];
        let reg = vec![
            reg_line("sensor_register", 10, 0),
            reg_line("sensor_heartbeat", 10, 2 * SECOND),
        ];
        let sensor_trace = vec![
            sensor(
                SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/a".to_string(),
                    write: true,
                },
            ),
            sensor(
                5 * SECOND,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
        ];
        let report = correlate(&product_trace, &sensor_trace, &reg, &Options::default());
        assert_eq!(
            report.counts.findings, 0,
            "the open after the replaced image and the silence are both explained"
        );
    }

    #[test]
    fn a_held_open_the_registered_sensor_never_reported_is_contradicted() {
        let product_trace = vec![
            session_with_sensor("/sensor.so"),
            product(
                SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/marker".to_string(),
                    write: true,
                },
            ),
            product(
                2 * SECOND,
                10,
                EventKind::NetworkConnect {
                    addr: "127.0.0.1".to_string(),
                    port: 9000,
                    host: None,
                },
            ),
        ];
        let reg = vec![reg_line("sensor_register", 10, 0)];
        // The product posture: the connection contradicts, the write open
        // waits for the research flag.
        let report = correlate(&product_trace, &[], &reg, &Options::default());
        assert_eq!(report.counts.findings, 1);
        assert!(report
            .findings
            .iter()
            .all(|f| f.kind == DiscrepancyKind::ActionContradicted));
        assert!(report.findings[0].detail.contains("127.0.0.1:9000"));

        // The research posture: the write open contradicts too.
        let report = correlate(
            &product_trace,
            &[],
            &reg,
            &Options {
                compare_write_opens: true,
                ..Options::default()
            },
        );
        assert_eq!(report.counts.findings, 2);
        assert!(report
            .findings
            .iter()
            .all(|f| f.kind == DiscrepancyKind::ActionContradicted));
        // The findings carry the time of their proving events: the open at
        // one second sorts before the connect at two.
        assert!(report.findings[0].detail.contains("/tmp/marker"));
        assert!(report.findings[1].detail.contains("127.0.0.1:9000"));
    }

    #[test]
    fn a_reported_open_consumes_its_match_and_a_refused_open_is_honest_quiet() {
        let product_trace = vec![
            product(
                0,
                1,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            product(
                SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/a".to_string(),
                    write: true,
                },
            ),
            product(
                2 * SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/refused".to_string(),
                    write: true,
                },
            ),
        ];
        // The sensor reported the first open, and nothing for the refused
        // one — which the kernel or the policy never let run.
        let sensor_trace = vec![sensor(
            3 * SECOND,
            10,
            EventKind::FileOpen {
                path: "/tmp/a".to_string(),
                write: true,
            },
        )];
        let refused = product(
            2 * SECOND,
            10,
            EventKind::PolicyDecision {
                action: Box::new(af_core::Action::FileOpen {
                    path: "/tmp/refused".to_string(),
                    write: true,
                }),
                verdict: Box::new(af_core::Verdict::from_matches(vec![af_core::RuleMatch {
                    rule_id: "test.refuse".to_string(),
                    title: "refuse".to_string(),
                    category: "test".to_string(),
                    risk: af_core::RiskLevel::Blocked,
                    decision: af_core::Decision::Deny,
                    reason: String::new(),
                    quarantine: false,
                }])),
                ancestry: vec![],
            },
        );
        let mut trace = product_trace.clone();
        trace.push(refused);
        let reg = vec![reg_line("sensor_register", 10, 0)];
        let report = correlate(&trace, &sensor_trace, &reg, &Options::default());
        assert_eq!(
            report.counts.findings, 0,
            "both sides agree, and a refused call never ran"
        );
    }

    #[test]
    fn a_thread_open_reports_under_the_leader_and_stays_quiet() {
        // Node and Python open files from thread pools: the external view
        // names the thread, the sensor names the group. Without the map a
        // normal thread pool would read as a contradiction.
        let product_trace = vec![
            product(
                0,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            product(
                SECOND,
                10,
                EventKind::ProcessFork {
                    child_pid: 11,
                    is_thread: true,
                },
            ),
            product(
                2 * SECOND,
                11,
                EventKind::FileOpen {
                    path: "/tmp/a".to_string(),
                    write: true,
                },
            ),
        ];
        let sensor_trace = vec![sensor(
            3 * SECOND,
            10,
            EventKind::FileOpen {
                path: "/tmp/a".to_string(),
                write: true,
            },
        )];
        let reg = vec![reg_line("sensor_register", 10, 0)];
        let report = correlate(&product_trace, &sensor_trace, &reg, &Options::default());
        assert_eq!(report.counts.findings, 0);
    }

    #[test]
    fn a_dynamic_child_with_the_preload_that_never_registered_is_unreported() {
        let mut child = ProcessInfo::from_pid(20);
        child.exe = Some("/tmp/payload".to_string());
        child.dynamic_link = Some(true);
        child.env = BTreeMap::from([("LD_PRELOAD".to_string(), "/sensor.so".to_string())]);
        let product_trace = vec![
            session_with_sensor("/sensor.so"),
            product(
                SECOND,
                20,
                EventKind::ProcessExec {
                    process: Box::new(child),
                },
            ),
        ];
        let reg = vec![reg_line("sensor_register", 1, 0)];
        let report = correlate(&product_trace, &[], &reg, &Options::default());
        assert_eq!(report.counts.findings, 1);
        assert_eq!(
            report.findings[0].kind,
            DiscrepancyKind::SpawnSeenUnreported
        );
        assert_eq!(report.findings[0].pid, 20);
    }

    #[test]
    fn static_children_and_stripped_children_and_registered_children_are_quiet() {
        let reg = vec![reg_line("sensor_register", 1, 0)];
        let mut base = vec![session_with_sensor("/sensor.so")];

        // A static child: no preload can reach it, and the fact says so.
        let mut statik = ProcessInfo::from_pid(30);
        statik.dynamic_link = Some(false);
        statik.env = BTreeMap::from([("LD_PRELOAD".to_string(), "/sensor.so".to_string())]);
        base.push(product(
            SECOND,
            30,
            EventKind::ProcessExec {
                process: Box::new(statik),
            },
        ));

        // A child that stripped the preload: M4 owns that fact.
        let mut stripped = ProcessInfo::from_pid(31);
        stripped.dynamic_link = Some(true);
        base.push(product(
            2 * SECOND,
            31,
            EventKind::ProcessExec {
                process: Box::new(stripped),
            },
        ));

        // A dynamic child that registered (posix_spawn registers without an
        // intent): quiet.
        let mut child = ProcessInfo::from_pid(32);
        child.dynamic_link = Some(true);
        child.env = BTreeMap::from([("LD_PRELOAD".to_string(), "/sensor.so".to_string())]);
        base.push(product(
            3 * SECOND,
            32,
            EventKind::ProcessExec {
                process: Box::new(child),
            },
        ));
        let reg_with_child = vec![
            reg_line("sensor_register", 1, 0),
            reg_line("sensor_register", 32, 3 * SECOND),
        ];

        let report = correlate(&base, &[], &reg_with_child, &Options::default());
        assert_eq!(
            report.counts.findings, 0,
            "a static child, a stripped child and a registered child all stay quiet"
        );

        // The same trace without the child registration fires exactly there.
        let report = correlate(&base, &[], &reg, &Options::default());
        assert_eq!(report.counts.findings, 1);
        assert_eq!(report.findings[0].pid, 32);
    }

    #[test]
    fn a_registration_before_the_exec_is_the_parent_not_the_successor() {
        // The unlink attack: the preloaded parent forks, the fork writes an
        // exec intent and registers for the child *before* the exec, and the
        // successor image loads no sensor because the library file is gone.
        // Only a registration at or after the exec stop proves the successor
        // loaded the sensor.
        let mut child = ProcessInfo::from_pid(40);
        child.exe = Some("/bin/sh".to_string());
        child.dynamic_link = Some(true);
        child.env = BTreeMap::from([("LD_PRELOAD".to_string(), "/sensor.so".to_string())]);
        let product_trace = vec![
            session_with_sensor("/sensor.so"),
            product(
                SECOND,
                40,
                EventKind::ProcessExec {
                    process: Box::new(child),
                },
            ),
        ];
        let before = vec![
            reg_line("sensor_register", 1, 0),
            // The fork registered one tick before the exec stop.
            RegLine {
                kind: "sensor_register".to_string(),
                instance: "i-fork".to_string(),
                pid: 40,
                ppid: 1,
                exe: "/tmp/parent".to_string(),
                session: "afw-test".to_string(),
                ts: SECOND - 1,
            },
        ];
        let report = correlate(&product_trace, &[], &before, &Options::default());
        assert_eq!(
            report.counts.findings, 1,
            "the successor image never registered"
        );
        assert_eq!(
            report.findings[0].kind,
            DiscrepancyKind::SpawnSeenUnreported
        );

        // The same run with the successor's constructor registration after
        // the exec stop: the sensor loaded, and the fact stays quiet.
        let mut after = before.clone();
        after.push(reg_line("sensor_register", 40, SECOND + 1));
        let report = correlate(&product_trace, &[], &after, &Options::default());
        assert_eq!(
            report.counts.findings, 0,
            "a successor that registered talks"
        );
    }

    #[test]
    fn the_loaders_own_opens_are_plumbing_and_the_programs_are_not() {
        // The window between an exec stop and the successor's registration:
        // the loader opens the program and its libraries, the sensor's
        // constructor opens its trace and its record, and none of it crosses
        // the interposed libc. After the registration the sensor is armed,
        // and a write open that crosses the kernel filter without crossing
        // libc is a contradiction — behind the research flag, because the
        // write comparison is not the product posture.
        let product_trace = vec![
            session_with_sensor("/sensor.so"),
            product(
                SECOND,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            // Plumbing: the sensor's own trace and record, opened raw.
            product(
                SECOND + 100,
                10,
                EventKind::FileOpen {
                    path: "/tmp/sensor.jsonl".to_string(),
                    write: true,
                },
            ),
            product(
                SECOND + 200,
                10,
                EventKind::FileOpen {
                    path: "/tmp/sensor.reg".to_string(),
                    write: true,
                },
            ),
            // The program, acting without libc.
            product(
                5 * SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/marker".to_string(),
                    write: true,
                },
            ),
        ];
        let reg = vec![reg_line("sensor_register", 10, SECOND + 1000)];
        let opts = Options {
            compare_write_opens: true,
            ..Options::default()
        };
        let report = correlate(&product_trace, &[], &reg, &opts);
        assert_eq!(report.counts.findings, 1);
        assert_eq!(report.findings[0].kind, DiscrepancyKind::ActionContradicted);
        assert!(
            report.findings[0].detail.contains("/tmp/marker"),
            "only the program's own open fires"
        );
    }

    #[test]
    fn a_reported_spawn_with_no_observed_exec_is_measured_and_expected_zero() {
        // The structurally impossible case, built on purpose: the sensor
        // reports an exec, never speaks again, and the process lives past
        // the window with no external exec.
        let product_trace = vec![
            product(
                0,
                1,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(1)),
                },
            ),
            product(
                10 * SECOND,
                10,
                EventKind::ProcessExit {
                    code: Some(0),
                    signal: None,
                    sid: None,
                },
            ),
        ];
        let reg = vec![reg_line("sensor_register", 10, 0)];
        let sensor_trace = vec![
            sensor(
                SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/a".to_string(),
                    write: true,
                },
            ),
            sensor(
                2 * SECOND,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
        ];
        let report = correlate(&product_trace, &sensor_trace, &reg, &Options::default());
        assert_eq!(report.counts.findings, 1);
        assert_eq!(
            report.findings[0].kind,
            DiscrepancyKind::SpawnReportedUnseen
        );

        // The everyday shape stays quiet: a shell probes a name, the exec
        // fails, the shell keeps talking and the external view sees nothing.
        let sensor_trace = vec![
            sensor(
                2 * SECOND,
                10,
                EventKind::ProcessExec {
                    process: Box::new(ProcessInfo::from_pid(10)),
                },
            ),
            sensor(
                3 * SECOND,
                10,
                EventKind::FileOpen {
                    path: "/tmp/a".to_string(),
                    write: true,
                },
            ),
        ];
        let report = correlate(&product_trace, &sensor_trace, &reg, &Options::default());
        assert_eq!(
            report.counts.findings, 0,
            "a failed exec with a living, talking process is normal"
        );
    }
}
