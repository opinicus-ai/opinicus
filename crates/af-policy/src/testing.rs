//! The tests that a rule file declares.
//!
//! A rule file carries its own tests. `agent-firewall policy test` runs them,
//! so a rule pack proves itself on the machine of the user and in the build.

use std::collections::{BTreeMap, BTreeSet};

use af_core::process::InputSource;
use af_core::{
    Action, AgentKind, AgentMeta, Decision, EvalContext, ProcessInfo, SessionId, SessionMemory,
    SessionMeta, TimestampNanos,
};

use crate::matcher::Subject;
use crate::source::{TestInputSource, TestProcess, TestSource, TestStep};
use crate::CompiledRule;

/// How many nanoseconds are in one second.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// One test that did not give the expected decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFailure {
    /// Identifier of the rule that declares the test.
    pub rule_id: String,
    /// Name of the test.
    pub test_name: String,
    /// The decision that the test expects.
    pub expected: Decision,
    /// The decision that the rule gave.
    pub actual: Decision,
    /// Where the rule came from.
    pub source: String,
}

impl std::fmt::Display for TestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): test `{}` expected `{}` but got `{}`",
            self.rule_id, self.source, self.test_name, self.expected, self.actual
        )
    }
}

/// The result of a whole test run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestReport {
    /// How many tests gave the expected decision.
    pub passed: usize,
    /// Every test that did not.
    pub failures: Vec<TestFailure>,
}

impl TestReport {
    /// Returns true when every test passed.
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// Returns how many tests ran.
    pub fn total(&self) -> usize {
        self.passed + self.failures.len()
    }
}

impl std::fmt::Display for TestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} of {} tests passed", self.passed, self.total())
    }
}

/// Everything that one declared test needs for an evaluation.
///
/// The structure owns its data, because [`EvalContext`] only borrows.
pub(crate) struct TestCase {
    session: SessionMeta,
    action: Action,
    process: ProcessInfo,
    ancestry: Vec<ProcessInfo>,
    ts: TimestampNanos,
}

impl TestCase {
    /// Returns the context of the test.
    pub(crate) fn context(&self) -> EvalContext<'_> {
        EvalContext::new(&self.session, &self.action, &self.process, &self.ancestry).at(self.ts)
    }
}

/// Runs every declared test of every rule.
///
/// A test with a `history` first plays its steps. The steps build the memory
/// of the session through the whole loaded set, exactly as a live session
/// does, because a mark often comes from another rule. The action of the test
/// itself is then judged **against its own rule only**, so another rule can
/// never hide a mistake.
pub(crate) fn run_tests(rules: &[CompiledRule]) -> TestReport {
    let mut report = TestReport::default();
    for rule in rules {
        for test in &rule.tests {
            let mut memory = build_memory(test);
            for step in build_history(test) {
                let subject = Subject::with_memory(&step.context(), &memory);
                let mut effects = Vec::new();
                for other in rules {
                    let (_, mut wanted) = other.evaluate_one(&subject);
                    effects.append(&mut wanted);
                }
                for effect in effects {
                    memory.apply(effect, step.ts);
                }
            }
            let case = build_case(test);
            let subject = Subject::with_memory(&case.context(), &memory);
            let (matched, _) = rule.evaluate_one(&subject);
            let actual = if matched {
                rule.decision
            } else {
                Decision::Allow
            };
            if actual == test.expect && matched == wants_match(test) {
                report.passed += 1;
            } else {
                report.failures.push(TestFailure {
                    rule_id: rule.id.clone(),
                    test_name: test.name.clone(),
                    expected: test.expect,
                    actual,
                    source: rule.source.clone(),
                });
            }
        }
    }
    report
}

/// Returns true when the test says that the rule must match.
///
/// A test that expects a decision which stops the action must match. A test
/// that expects `allow` must not match, because a quiet action matches no
/// rule. A rule that reports without stopping needs `expect_match: true`.
pub(crate) fn wants_match(test: &TestSource) -> bool {
    test.expect_match.unwrap_or(test.expect != Decision::Allow)
}

/// Builds the context of one declared test.
///
/// The action of the test comes after every history step. Without an explicit
/// `at_seconds` the steps stand one second apart, so a test that writes no
/// time still gets a stable and readable order.
pub(crate) fn build_case(test: &TestSource) -> TestCase {
    let process = to_process(&test.process, 1);
    let ancestry: Vec<ProcessInfo> = test
        .ancestry
        .iter()
        .enumerate()
        .map(|(index, p)| to_process(p, 2 + index as i32))
        .collect();
    let action = to_action(DeclaredAction::of_test(test), &process);
    let session = test_session(&process, &ancestry, &test.baseline, &SessionFacts::of(test));
    let ts = seconds(test.at_seconds.unwrap_or_else(|| history_length(test)));
    TestCase {
        session,
        action,
        process,
        ancestry,
        ts,
    }
}

/// Builds the memory that the test starts with.
pub(crate) fn build_memory(test: &TestSource) -> SessionMemory {
    let mut sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, values) in &test.baseline {
        sets.insert(name.clone(), values.iter().cloned().collect());
    }
    SessionMemory::with_baseline(sets)
}

/// Builds every step that happens before the action of the test.
///
/// A step with `repeat` becomes that many steps, one second apart, which lets
/// a test write twenty deletes without twenty blocks of text.
pub(crate) fn build_history(test: &TestSource) -> Vec<TestCase> {
    let mut out: Vec<TestCase> = Vec::new();
    let mut clock = 0u64;
    for step in &test.history {
        let times = step.repeat.unwrap_or(1).max(1) as u64;
        let start = step.at_seconds.unwrap_or(clock);
        for index in 0..times {
            out.push(build_step(step, start + index));
        }
        clock = start + times;
    }
    out
}

/// Returns the default time of the action of the test, in seconds.
fn history_length(test: &TestSource) -> u64 {
    let mut clock = 0u64;
    for step in &test.history {
        let times = step.repeat.unwrap_or(1).max(1) as u64;
        clock = step.at_seconds.unwrap_or(clock) + times;
    }
    clock
}

/// Builds the context of one history step.
fn build_step(step: &TestStep, at_seconds: u64) -> TestCase {
    let process = to_process(&step.process, 1);
    let ancestry: Vec<ProcessInfo> = step
        .ancestry
        .iter()
        .enumerate()
        .map(|(index, p)| to_process(p, 2 + index as i32))
        .collect();
    let action = to_action(DeclaredAction::of_step(step), &process);
    let session = test_session(&process, &ancestry, &BTreeMap::new(), &SessionFacts::none());
    TestCase {
        session,
        action,
        process,
        ancestry,
        ts: seconds(at_seconds),
    }
}

/// Turns whole seconds into the nanoseconds that an event carries.
fn seconds(value: u64) -> TimestampNanos {
    value.saturating_mul(NANOS_PER_SECOND)
}

/// The B.5 facts that one declared test seeds into its session.
struct SessionFacts<'a> {
    /// Process identifier of the monitor itself, when the test names one.
    monitor_pid: Option<i32>,
    /// The sensor instances that had registered at session start.
    sensor_instances: &'a [i32],
    /// Path of the trace file that the session writes to.
    trace_path: Option<&'a str>,
    /// Path of the in-process sensor's trace file.
    sensor_trace_path: Option<&'a str>,
    /// Path of the sensor registration record.
    sensor_registration_path: Option<&'a str>,
}

impl<'a> SessionFacts<'a> {
    /// The facts of a test that declares no B.5 facts at all.
    fn none() -> Self {
        Self {
            monitor_pid: None,
            sensor_instances: &[],
            trace_path: None,
            sensor_trace_path: None,
            sensor_registration_path: None,
        }
    }

    /// Reads the facts that a test declares on itself.
    fn of(test: &'a TestSource) -> Self {
        Self {
            monitor_pid: test.monitor_pid,
            sensor_instances: &test.sensor_instances,
            trace_path: test.trace_path.as_deref(),
            sensor_trace_path: test.sensor_trace_path.as_deref(),
            sensor_registration_path: test.sensor_registration_path.as_deref(),
        }
    }
}

/// Makes the session metadata of a test.
///
/// The value holds no clock and no random number, so a test run is
/// repeatable.
///
/// The **last** entry of the ancestry is the root of the session, exactly as
/// a live session builds it: the ancestry runs from the nearest parent to the
/// process that the firewall launched. The metadata therefore names that
/// process as `root_pid`, so a rule with the scope `subtree` is judged
/// against the same shape that a real session has. A test with no ancestry
/// runs its process as the root itself.
fn test_session(
    process: &ProcessInfo,
    ancestry: &[ProcessInfo],
    baseline: &BTreeMap<String, Vec<String>>,
    facts: &SessionFacts<'_>,
) -> SessionMeta {
    let mut sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, values) in baseline {
        sets.insert(name.clone(), values.iter().cloned().collect());
    }
    // The sensor facts exist when the test names anything of the sensor: a
    // session can run with the sensor and no registered instance yet, which
    // a test with only a sensor path and no instance writes.
    let has_sensor = !facts.sensor_instances.is_empty()
        || facts.sensor_trace_path.is_some()
        || facts.sensor_registration_path.is_some();
    SessionMeta {
        session_id: SessionId::from("afw-policy-test"),
        started_at: 0,
        root_pid: ancestry.last().map(|p| p.pid).unwrap_or(process.pid),
        command: vec!["policy-test".to_string()],
        cwd: process.cwd.clone().unwrap_or_else(|| "/".to_string()),
        agent: AgentMeta {
            kind: AgentKind::Shell,
            version: None,
            agent_session_id: None,
            tool_call_id: None,
        },
        schema_version: af_core::EVENT_SCHEMA_VERSION,
        baseline: sets,
        detection: None,
        monitor_pid: facts.monitor_pid.unwrap_or(0),
        sensor: has_sensor.then(|| af_core::SensorMeta {
            preload: "/research/spikes/inprocess/libafsensor.so".to_string(),
            instances: facts.sensor_instances.to_vec(),
            trace: facts.sensor_trace_path.map(str::to_string),
            registration: facts.sensor_registration_path.map(str::to_string),
        }),
        trace: facts.trace_path.map(str::to_string),
    }
}

/// Makes a process record from the short form of a test file.
fn to_process(source: &TestProcess, default_pid: i32) -> ProcessInfo {
    let comm = source.comm.clone().unwrap_or_else(|| {
        source
            .exe
            .as_deref()
            .or_else(|| source.argv.first().map(|a| a.as_str()))
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
            .unwrap_or_default()
    });
    let argv = if source.argv.is_empty() && !comm.is_empty() {
        vec![comm.clone()]
    } else {
        source.argv.clone()
    };
    ProcessInfo {
        pid: source.pid.unwrap_or(default_pid),
        ppid: source.ppid,
        start_ticks: 0,
        exe: source.exe.clone(),
        comm,
        argv,
        cwd: source.cwd.clone(),
        env: source.env.clone(),
        sid: None,
        dynamic_link: None,
    }
}

/// The action that a declared test, or one of its history steps, performs.
///
/// A test and a step name their action with the same fields, so the two
/// share one carrier and [`to_action`] reads one value instead of eight
/// positions.
pub(crate) struct DeclaredAction<'a> {
    file_open: Option<&'a crate::source::TestFileOpen>,
    connect: Option<&'a crate::source::TestConnect>,
    input: Option<&'a crate::source::TestInput>,
    signal_send: Option<&'a crate::source::TestSignalSend>,
    io_uring: Option<&'a crate::source::TestIoUring>,
    tamper: Option<&'a crate::source::TestTamper>,
    discrepancy: Option<&'a crate::source::TestDiscrepancy>,
}

impl<'a> DeclaredAction<'a> {
    /// Reads the action that the test itself declares.
    fn of_test(test: &'a TestSource) -> Self {
        Self {
            file_open: test.file_open.as_ref(),
            connect: test.connect.as_ref(),
            input: test.input.as_ref(),
            signal_send: test.signal_send.as_ref(),
            io_uring: test.io_uring.as_ref(),
            tamper: test.tamper.as_ref(),
            discrepancy: test.discrepancy.as_ref(),
        }
    }

    /// Reads the action that one history step declares.
    fn of_step(step: &'a TestStep) -> Self {
        Self {
            file_open: step.file_open.as_ref(),
            connect: step.connect.as_ref(),
            input: step.input.as_ref(),
            signal_send: step.signal_send.as_ref(),
            io_uring: step.io_uring.as_ref(),
            tamper: step.tamper.as_ref(),
            discrepancy: step.discrepancy.as_ref(),
        }
    }
}

/// Makes the action of a test.
///
/// A test that names no other action starts a program, because that is the
/// action that most rules watch.
fn to_action(declared: DeclaredAction<'_>, process: &ProcessInfo) -> Action {
    let DeclaredAction {
        file_open,
        connect,
        input,
        signal_send,
        io_uring,
        tamper,
        discrepancy,
    } = declared;
    if let Some(open) = file_open {
        return Action::FileOpen {
            path: open.path.clone(),
            write: open.write,
        };
    }
    if let Some(connect) = connect {
        return Action::NetworkConnect {
            host: connect.host.clone(),
            addr: connect
                .addr
                .clone()
                .or_else(|| connect.host.clone())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            port: connect.port,
        };
    }
    if let Some(input) = input {
        return Action::Input {
            source: match input.source.unwrap_or(TestInputSource::Stdin) {
                TestInputSource::Argv => InputSource::Argv,
                TestInputSource::Stdin => InputSource::Stdin,
                TestInputSource::File => InputSource::File,
                TestInputSource::Environment => InputSource::Environment,
            },
            data: input.data.clone(),
        };
    }
    if let Some(signal) = signal_send {
        return Action::SignalSend {
            target: signal.target,
            signal: signal.signal,
        };
    }
    if let Some(ring) = io_uring {
        return Action::IoUring { call: ring.call };
    }
    if let Some(tamper) = tamper {
        return Action::Tamper {
            kind: tamper.kind,
            detail: tamper
                .detail
                .clone()
                .unwrap_or_else(|| tamper.kind.label().to_string()),
        };
    }
    if let Some(discrepancy) = discrepancy {
        return Action::Discrepancy {
            kind: discrepancy.kind,
            detail: discrepancy
                .detail
                .clone()
                .unwrap_or_else(|| discrepancy.kind.label().to_string()),
        };
    }
    Action::Exec {
        exe: process.exe.clone(),
        program: process.program_name().to_string(),
        argv: process.argv.clone(),
        cwd: process.cwd.clone(),
        env: process.env.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_case, build_history, build_memory};
    use crate::source::TestSource;
    use crate::PolicySet;
    use af_core::{Decision, PolicyEngine, SessionMemory};

    /// Plays the history of a test through the whole pack.
    fn memory_of(set: &PolicySet, test: &TestSource) -> SessionMemory {
        let mut memory = build_memory(test);
        for step in build_history(test) {
            let ctx = step.context();
            let (_, effects) = set.evaluate_with_memory(&ctx, &memory);
            for effect in effects {
                memory.apply(effect, ctx.ts);
            }
        }
        memory
    }

    /// Runs every declared test against the whole built-in pack.
    ///
    /// `run_tests` looks at one rule only. This test looks at all rules
    /// together, so it finds a rule that fires on the example of another
    /// rule. A quiet example must stay quiet in the whole pack, and a strong
    /// example must stay at least as strong.
    #[test]
    fn no_rule_of_the_pack_fires_on_a_quiet_example_of_another_rule() {
        let set = PolicySet::builtin().expect("the built-in pack loads");
        let mut problems: Vec<String> = Vec::new();
        for rule in &set.rules {
            for test in &rule.tests {
                let memory = memory_of(&set, test);
                let case = build_case(test);
                let ctx = case.context();
                let (verdict, _) = set.evaluate_with_memory(&ctx, &memory);
                let names: Vec<&str> = verdict.matches.iter().map(|m| m.rule_id.as_str()).collect();
                if test.expect == Decision::Allow {
                    if verdict.decision != Decision::Allow {
                        problems.push(format!(
                            "`{}` test `{}` is quiet for its own rule, but the pack answers {:?} from {names:?}",
                            rule.id, test.name, verdict.decision
                        ));
                    }
                } else if verdict.decision < test.expect {
                    problems.push(format!(
                        "`{}` test `{}` wants {:?}, but the pack answers {:?} from {names:?}",
                        rule.id, test.name, test.expect, verdict.decision
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}
