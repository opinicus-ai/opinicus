# Milestones

The execution plan. [DIRECTION.md](DIRECTION.md) holds the destination and
the principles; this document holds the order of the work and the gate each
step must pass. Where the two differ, DIRECTION.md wins.

Status is updated in place, ledger-style. A milestone is done when the
measurement of its exit gate is committed next to runnable code — not when
the code compiles. A gate that fails is a result: it gets recorded, and the
plan absorbs it.

| status | meaning |
| --- | --- |
| planned | not started |
| running | work has started |
| gate | the measurement exists; the decision is open |
| done | gate passed and recorded |
| failed | gate failed and recorded; scope or direction adjusts |

## The ladder

| id | milestone | workstreams | question it answers | depends on | size |
| --- | --- | --- | --- | --- | --- |
| M1 | The bypass harness | W2 | What does the shipping firewall actually hold, see, and miss? | — | M |
| M2 | The in-process sensor | W1 + W2 rerun | What do semantics close to the agent add, and is the sensor worth shipping? | M1 | M |
| M3 | Agent identity | W3, W4 | Which process is the agent, and does the identity hold through the tree? | — | M |
| ML | Quiet by construction (Landlock, L0) | — | Which questions can the kernel answer so the user never sees them? | M1 | S |
| M4 | Tamper and quarantine | B.5, B.6, W6 | Can the firewall notice its own visibility failing, and stop the tree first? | M2, M3 | M |
| M5 | The correlation engine | W5 | Do expected-vs-observed discrepancies survive contact with normal sessions? | M2 | M |
| M6 | Telemetry and the alpha | W7 | What can we collect safely, and does the whole hold together as a release? | M4, M5, ML | M |
| M7 | The Windows survey | W8 | What is the Windows shape of sensor and observer? | — | S |

M3 and ML may run in parallel with M1 and M2; they touch no shared code.
Everything else runs in ladder order. M7 is never blocking.

---

## M1 — The bypass harness

**Goal.** One matrix, two sensors. The shipping firewall is exec `ptrace`
plus the `seccomp` filter. Before any new sensor is argued for, measure what
these two hold, see, and miss — with attacks on purpose, not by anecdote.

**Deliverables.**

* `research/bypass/`: a suite of small controlled programs, one per
  technique. Seed list, each grounded in a measurement or a catalogue
  scenario: a static binary; raw `syscall()` file and network access from a
  running program; `setsid` and double-fork; a process that outlives the
  session; `io_uring` batch I/O; delete and rename (no event kind exists);
  dangerous content passed by file name instead of argv; a read of a
  credential file under both filter modes; an attempt to find and kill the
  monitor.
* A benign corpus: a scripted normal dev session — `cargo build`, `npm
  test`, `git`, `kubectl get` — that must never trigger anything.
* The matrix: technique × sensor mode (`write-only`, `all-opens`, `off`),
  each cell `held | seen | silent`, with the rule that fired or the reason
  none could. Every row cites the `evade` scenario it maps to, where one
  exists.

**Exit gate.** The matrix is committed with runnable code and a
`FINDINGS.md`; the benign corpus produces zero questions in the same run;
every `silent` cell names the mechanism that would be needed to see it.

**Unlocks.** The true rank of the external stack's gaps; the job description
for the in-process sensor (M2); the tamper techniques M4 must sense; the rows
that decide whether correlation has anything to catch (M5).

## M2 — The in-process sensor

**Goal.** The `LD_PRELOAD` shim of DIRECTION.md §3.1, measured as a sensor.
It reports. It never decides.

**Deliverables.**

* `research/spikes/inprocess/`: a shim that emits `af-core` events — exec
  family, file access, network libc calls, `dlopen`, environment
  manipulation — with propagation into descendants where it can, and a
  registration record so the firewall knows exactly which sensor instances
  it installed. That registration is the B.5 fact that M4 and M5 key on.
* The M1 matrix re-run with the shim active: which cells move from `silent`
  to `seen`, and which move to `held` — the shim itself never holds; a hold
  can only come from correlation with an external sensor.
* Bench numbers for the shim, and the semantic gain in one number: what
  fraction of the benign corpus's interesting actions the sensor reports
  that argv-only cannot see (stdin context, about-to-exec).

**Exit gate.** Schema-valid events in a trace; the matrix rows updated;
overhead measured; and the DECISIONS test already applied — sensor silence,
keyed to installed instances, fires zero times on the benign corpus. The
gate decides: keep the sensor in the product, or demote it to research
telemetry. Both are acceptable results.

## M3 — Agent identity

**Goal.** Answer question 1 of DIRECTION.md §11 with numbers: how reliably
can we identify AI-agent root processes, and does the identity hold through
the tree?

**Deliverables.**

* A detector interface in `af-core` (plugin shape, confidence score) and the
  first detectors: known executables and argv patterns, package-manager
  installation metadata, dependency manifests, characteristic environment
  variables.
* Identity as a fact of the provenance graph: the tagged root, propagated to
  every descendant; events carry the agent.
* Escape detection as the negative case: a descendant that detaches from the
  tree (`setsid`, double-fork) is flagged as *unlinked*, never as *foreign*
  (this is the B.6 liveness fact, shared with M4).

**Exit gate.** On a fixture corpus of agent and non-agent commands, precision
and recall are measured and committed; a normal non-agent dev session
receives zero agent tags; a fixture escape is flagged. Quiet applies to
identity too: a false agent tag is worse than no tag, because everything
downstream keys on it.

## ML — Quiet by construction (Landlock, L0)

**Goal.** Ship the one mechanism that removes questions instead of asking
them. Measured at 1.0×, sound by construction, enforced in the kernel
(DETECTION-RESEARCH §4).

**Deliverables.**

* Re-measure the current 144-rule pack: which `approval_required` and `deny`
  rules are "always no, everywhere" and can move into the kernel. The spike
  measured 10 of the earlier 69-rule pack; today's number is the gate's
  input.
* The L2 explainer: when the kernel refuses, the session names the rule the
  kernel enforced. DETECTION-RESEARCH is explicit that an unexplained
  `EACCES` is how the cheapest layer gets switched off.
* e2e: a credential read two shells deep fails with no prompt, and the
  session explains why.

**Exit gate.** The count of questions removed, measured on the pack and on
the benign corpus; the bench shows no measurable cost; zero new questions
added. This milestone can only shrink the interruption budget.

## M4 — Tamper and quarantine

**Goal.** Fail-closed becomes sensed. Today the tree dies with the monitor
(`EXITKILL`) and a monitor-less call breaks (`ENOSYS`); nothing notices the
attempt. DIRECTION.md §6 makes the attempt a high-severity signal, and the
decision log binds how: keyed to the firewall's own identity, governed by
the budget.

**Deliverables.**

* B.5 facts: a rule can ask which processes are the monitor, the session
  root, and this session's sensor instances.
* B.6 liveness: a process that outlived the session; a killed subtree that
  came back; a descendant that escaped its ancestry (shared with M3).
* Tamper events for the seeded techniques of M1: find and kill the monitor,
  escape the tree, spawn after sensor registration, strip the preload
  configuration once M2 ships.
* The quarantine flow: suspend the subtree, show the evidence, take the
  ruling — allow once, create an exception, terminate — and record all of it
  in the trace like any policy decision.

**Exit gate.** Seeded tamper fires every time in the e2e; the benign corpus
and the normal-session recordings of M1/M2 produce zero quarantines; every
tamper rule carries its negative test. The gate is the negative test, not
the positive one: a quarantine that fires on normal work is the
product-killing failure.

## M5 — The correlation engine

**Goal.** Question 7 and DIRECTION.md §3.4: do expected-vs-observed
discrepancies survive contact with real sessions?

**Deliverables.**

* Discrepancy events in the schema: a sensor-silent subtree; a spawn
  reported but not seen, or seen but not reported; an action contradicted.
* Rules for the discrepancies that M1 and M2 showed are real, each with its
  negative test.

**Exit gate.** A ledger-style table: firing rate on the bypass corpus versus
firing rate on the benign corpus. A rule ships only if the second number is
zero. If no rule passes, the engine is demoted to research telemetry and the
result is recorded — a null result re-plans M6, it does not fail the
direction.

## M6 — Telemetry and the alpha

**Goal.** The first release, under DIRECTION.md §7 and the decision log:
opt-in, never a condition, redaction by design.

**Deliverables.**

* The redaction-first packaging spec: what a sample may contain, what is
  dropped by default, what is pseudonymized, and how a sample is inspectable
  before it leaves.
* The consent flow: off by default, granular, revocable. With telemetry off,
  the product is complete.
* The alpha itself: Linux, launcher mode, whichever sensors passed their
  gates, agent identity, tamper and quarantine, the deterministic engine,
  local traces, the alpha banner — *not a production security boundary* —
  and the disclosure.

**Exit gate.** The full suite is green — fmt, clippy, tests, e2e,
quiet-check, `check.py`; the banner and the limits are documented; a sample
can be generated, inspected, and destroyed locally with the backend
untouched. The research backend and the analysis-agent automation are not in
this milestone; the manual workflow of `research/threats/` continues as the
pipeline's front end.

## M7 — The Windows survey

**Goal.** Shape, not code. What is the Windows counterpart of sensor
(hooking) and observer (an independent view)?

**Deliverables.** A survey in `research/spikes/windows-notes/`: the
candidate hooking layers (Win32, `ntdll` trampolines), the candidate
independent observers, the evasion realities of each, and a schema review —
can `af-core` carry what Windows would produce?

**Exit gate.** A chosen candidate and the list of questions that only a
Windows spike can answer. No code, and no schema commitments beyond the
review.

---

## The rule that moves a milestone

* A milestone is done when its exit-gate measurement is committed next to
  runnable code.
* No milestone starts before its dependencies' gates are recorded; the
  parallel pairs of the ladder are the only exception.
* Every milestone re-runs the shared benchmark. Overhead numbers never drift
  silently.
* The interruption budget governs every milestone that can ask a question.
  Quiet is the feature; the benign corpus is the test.

## Continuous tracks

* **Threat research.** The workflow of `research/threats/` keeps running.
  New scenarios become rules only under the budget.
* **The bench.** Every milestone re-measures, so the numbers of
  DETECTION-RESEARCH stay honest.
* **The ledger.** `research/threats/check.py` stays green, and the blocked
  count is a progress metric: 74 scenarios are blocked on observables today.
  Each sensor that lands unblocks a counted set.

## Not yet, on purpose

macOS. Attach-mode observation of an agent the firewall did not launch (an
M3 follow-up, measured before trusted). The enterprise tier — privileged
service, central policy, Group Policy. Network content inspection. `io_uring`
coverage. The research backend and the analysis-agent automation. Any Windows
code.

## Status

| date | note |
| --- | --- |
| 2026-08-30 | plan adopted; M1–M7 planned; the Linux PoC (exec `ptrace` + `seccomp` filter, session memory, the 144-rule pack, replay, the threat catalogue) is the standing baseline |
| 2026-08-30 | the ladder is tracked as rohrpost tickets under epic `[af]` (`rp tree`, `rp ready`); each `[af-N]` ticket carries its milestone's deliverables and exit gate |
| 2026-08-31 | **M1 done.** The bypass matrix shipped (`research/bypass/`): 12 actions against the product posture — 1 held, 7 seen, 4 silent, each silent cell with its mechanism; the corpus ran with zero questions in all three modes. Two new findings: the input capture misses versioned interpreter names (python3.14), and a killed monitor erases its own evidence. Feeds M2, M4, M5 and the next threat-research run |
| 2026-08-31 | **M2 done.** The in-process sensor shipped as a spike (`research/spikes/inprocess/`) and the gate said **keep**: the pydrop and byfile-unknown rows moved from silent to seen in all three modes (delete-rename and cred-read moved too — 11 of 14 gap cells); the semantic gain is 98 % (1205 of 1231 interesting corpus actions invisible to argv); the corpus ran with zero questions and zero sensor-silence in all three modes; the sensor costs 1.46×/1.77×/1.42× alone and ×1.13–×1.29 on top of the product. The af-core schema gained `file_read`, `file_delete`, `file_rename`, `library_load`, `env_change`; no rule matches them yet. The registration record is durable — in the kill-monitor run the product trace kept 1 line, the sensor trace kept 37. Feeds M4 (B.5 instances, durable evidence) and M5 (correlation) |
| 2026-08-31 | **ML done.** The kernel floor shipped: a Landlock ruleset in `af-monitor`, enacted before the first program runs (`--landlock off` is the switch), with the L2 explainer (`kernel_denied` names the rule class behind every `EACCES` the floor causes). The 147-rule pack re-measured against the shipped floor (`research/spikes/landlock/tests/count-rules.py`): **6 of 61 questions answered by the kernel (10%)**, 3 of 9 `deny` rules kernel-backed; the count is smaller than the spike's paper 24% because the bar moved — a class rides only when no session shape lets the action through, and the `.ssh`-under-`/tmp` case proved the bar was needed. The benign corpus ran with zero questions in all three filter modes under the floor; the bench shows 0.98×–1.03× of the product's own time (`research/bench/floor.sh`); e2e proves the credential read two shells deep fails with no prompt and is explained (K1–K8) |
| 2026-08-31 | **M3 done.** Agent identity shipped: a `Detector` trait and registry in `af-core::identity` (noisy OR over detectors, tag at ≥ 0.75) with five built-in detectors (executables, argv patterns, install layouts, dependency manifests, environment markers); the tagged root carries its assessment in `SessionStart`, every event of the session carries the tag, and a descendant that called `setsid` is flagged `process_unlinked` with the measured session ids — unlinked, never foreign. Measured on a synthetic fixture corpus (no real agent installed, honestly labeled): precision 1.000 (0 of 30 non-agent fixtures tagged), recall 0.957 (the one miss is the bare name `pi`); the benign corpus ran with zero questions **and zero agent tags** in all three modes; the escape fixture raised the flag at the re-exec and at the detaching parent's exit, and the `outlive` daemon raised it at its own exit. No rule consumes the identity yet. Evidence: `research/detection/` |
| 2026-08-31 | **M4 done.** Tamper sensing and the quarantine flow shipped. The B.5 facts are rule-visible (`SessionMeta` carries the monitor pid and the sensor facts; the matcher gained `signal_target`), the kernel filter now holds `kill`/`tkill`/`tgkill` against the monitor pid so the signal is judged **before it runs**, and four sensed shapes reach the engine as actions (`signal_send`, `tamper`) judged by the new 5-rule `policies/tamper.yaml`; a rule with `quarantine: true` suspends the whole tree (`SIGSTOP`, group stops held), shows the evidence and takes one ruling, all of it in the trace. The recorder writes every process event through, so a SIGKILLed monitor leaves the record (2 lines against M1's 1, filter and floor off). **The negative test decided one rule**: the detach first quarantined, and the corpus refused it — `git maintenance run --detach` raises the same fact on every commit — so detach and outlive report and never ask. Gate (`research/bypass/tamper.sh`, 3 runs, identical): kill-monitor 1/1/1, escape 3 facts/0 quarantines, respawn 2/2/2, strip-preload 1/1/1 — 4 of 4 seeded techniques; the benign corpus: zero questions, zero agent tags, **zero quarantines** in all three modes, with and without the sensor (M2 corpus gate re-run green); bench A/B pre/post M4: 1.00×–1.02×, inside noise. Evidence: `research/bypass/FINDINGS.md` (After M4), `tests/e2e.sh` T1–T18, `docs/ARCHITECTURE.md` §3d |
| 2026-08-31 | **M5 done.** The correlation engine shipped (`agent-firewall correlate`, `crates/af-correlate`): it reads the monitor's trace against the sensor's trace and registration record and raises `discrepancy` events (4 kinds) that `policies/correlation.yaml` judges — the first post-hoc judge over recorded pairs. Gate (`research/bypass/correlate.sh`, 3 runs, identical): silent-subtree 1/0, unreported-spawn 2/0, contradicted connection 1/0 (bypass/benign) — two rules quarantine, one reports; the benign corpus fired **zero** in all three filter modes (zero questions, zero quarantines held). The gate refused the write-open comparison with numbers (30 firings on one normal session: mkstemp-class internals, reflog double-opens, failed `/dev/tty` probes) — demoted to `--compare-write-opens` research telemetry; `spawn_reported_unseen` measured 0/0 (the exec stop is a kernel guarantee) and ships no rule; the freeze technique measured a product defense (the monitor continues a self-stopped tracee). The monitor now reads the `dynamic_link` fact at the exec stop; e2e T19–T22 proves the emitted findings replay. Evidence: `research/bypass/FINDINGS.md` (After M5), `docs/ARCHITECTURE.md` §3e, `docs/DECISIONS.md` (2026-08-31) |
| 2026-08-31 | **M6 done.** Telemetry and the alpha shipped: `crates/af-telemetry` with the `agent-firewall telemetry` family (status/on/off/sample/inspect/destroy) and `run --telemetry`. Consent is off by default, granular over five scopes (tree, actions, content, env, identity), revocable, kept in one local file that no other command reads — with telemetry off the product is complete. A sample centers on a trigger (quarantine, tamper, signal to the monitor, discrepancy, question, decision above allow) with a ±20-event window that merges on overlap; every field is scope-gated, secret-redacted (the monitor's env pattern of RESEARCH.md §4 generalized to every free text) and pseudonymized (session → `s-<hash>`, pids → `p1…`, home/login/host masked, time → ms offsets); environment values, the baseline and absolute time never travel in any scope. **Nothing is sent anywhere**: `cargo tree -p af-telemetry` names `af-core`, `serde`, `serde_json` only; the research backend does not exist, not as a stub. The alpha banner (*not a production security boundary*) prints before every `run` and in `doctor`, with the disclosure in README `The alpha` and the packaging spec in `docs/TELEMETRY.md`. Gate: fmt + clippy clean, **361 tests green** (26 suites), e2e **54/54**, the benign corpus **zero questions, zero agent tags, zero quarantines** in all three filter modes, `check.py` agrees (76 incidents, 200 scenarios); a sample generated, inspected and destroyed locally with the backend untouched (CLI test `a_sample_is_generated_inspected_and_destroyed_locally`, `run --telemetry` packages without a trace file; the crate test `no_secret_baseline_session_id_or_raw_pid_reaches_the_sample_text` proves the negative half on a session carrying a secret on the command line, in the environment, on stdin and in the baseline). No git tag, no version bump, nothing published. Evidence: `docs/TELEMETRY.md`, `docs/ARCHITECTURE.md` §3f, `crates/af-telemetry/tests/sample.rs`, `crates/af-cli/tests/cli.rs` |
| 2026-08-31 | **M7 done.** The Windows survey shipped on paper (`research/spikes/windows-notes/`), and the gate is satisfied by two decisions: **the sensor candidate is a launch-injected DLL with Detours-style inline trampolines on the `ntdll` syscall stubs** — one chokepoint every process maps, where the Win32 layer is a per-module surface a native caller skips — and **the observer candidate for the no-admin edition is the launch loop** (`DEBUG_PROCESS` debug events, which suspend the whole process before it runs user-mode code, plus a job object with `KILL_ON_JOB_CLOSE` as the `EXITKILL` analogue), with ETW as the assurance tier and WFP/minifilter as the enterprise tier. The headline finding is a hole the plan must absorb: **Windows has no unprivileged equivalent of the shipped `seccomp`+Landlock pair** — every kernel-side observer is behind elevation — so the unprivileged product rests on a hook (a sensor, never a boundary), a detectable debug loop and a job object. The schema review says the M2 sensor contract ports field for field while the monitor half is where the Linux-isms live (`sid`, `dynamic_link`, signal numbers, the LSM floor), and names the gaps: registry (largest), handles and delete-on-close, the ETW provider as a fact, image hashes, token facts, path normalization. Eight measured questions for a Windows spike close the survey. Nothing was run (no Windows host), every Windows claim cites Microsoft documentation, no code, no schema commitment, nothing blocking
