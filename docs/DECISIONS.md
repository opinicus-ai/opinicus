# Decision log

Dated records of decisions that bind later work. Newest first. A decision
here overrides older prose in other documents until a newer entry says
otherwise. Each entry names its evidence.

---



## 2026-09-01 — The Rohrpost incident is recorded, and the store gets a snapshot rule

On 2026-08-31 the repository lost uncommitted ticketing state during a
review window that was supposed to be read-only, and a commit message
described a filing its own commit did not contain. This entry records what
is established, what is not, and the rules adopted so that a future loss is
at least detectable.

**Established** (evidence: [PROJECT-REVIEW.md](PROJECT-REVIEW.md) §2.5).
Commit `c7ca6f0` (2026-08-31 22:26:07) says it files `[af-9]` "as
AF-an4nm7", but the commit touches only `research/threats/LEDGER.md` and
`research/threats/scenarios/evade.md` — no `.rohrpost` change. At 22:41,
when the first review workflow started, the working tree held
`.rohrpost/log.jsonl` and `.rohrpost/tickets.jsonl` modified and
uncommitted: an open ticket `AF-an4nm7` ("[af-9] Sense audit-trail
tampering: trace writes, history and transcript erasure") and one more log
event — ten tickets and 34 events against HEAD's nine and 33. Both files'
mtimes fall inside the review window (22:55:34). By 23:31 the tree was
clean and matched HEAD exactly; the ticket existed nowhere in tracked
state, and its title survived only in a review transcript. What is proven:
the uncommitted state of an open ticket and one log event no longer exists,
was destroyed during a window that was supposed to be read-only, and the
HEAD commit message misdescribed its own content.

**Not established.** What destroyed the state. A `git` path-restore (which
leaves no reflog entry), an `rp` operation, and human action all remain
possible; no available evidence distinguishes them, and this entry does not
choose. The read-only `rp` commands are excluded as re-writers — in this
window, not the original one: on 2026-09-01, `rp ready`, `rp list`,
`rp log`, `rp stats` and `rp doctor` (rohrpost 0.1.0) left the store
byte-identical at every hash — `log.jsonl`
`9d1b92b011f4f50406d3bcc8e31920e24d9ad6c23b2310a72b2392d4e4eda433`,
`tickets.jsonl`
`b20afed972eeef9ba41ef2d328914baccc1c97bbf04d5ec291df74f737956ef1` —
with `rp doctor` all clear, including `snapshot_matches`: a fresh fold of
the 49-event log reproduces the 24-ticket snapshot (cold fold 0.757 ms,
median). Neither "nothing was lost" nor any specific content loss beyond
the record above is claimed.

**Rules adopted.**

* **Snapshot before any agent workflow.** `scripts/rohrpost-snapshot.sh`
  records the commit, the `.rohrpost` porcelain status and the sha256 of
  both store files under `.rohrpost/snapshots/`; its `--check` re-hashes
  and exits non-zero on drift. Read-only means byte-identical, proven,
  not assumed. Snapshots are local fingerprints, not history.
* **Tickets live committed.** A ticket that exists only in the working
  tree does not exist. An `rp` operation that creates or changes a ticket
  is committed in the same work unit, before any other workflow runs
  against the repository.
* **A commit message matches its commit.** No message may claim a filing
  or a change its commit does not contain. A wrong message is corrected by
  a follow-up commit that names it; history is not rewritten.

Evidence: [PROJECT-REVIEW.md](PROJECT-REVIEW.md) §2.5 and §8 (P0-8); the
hash-stability measurement above; snapshot `20260901T002617Z` (rev
`3450cf8`), whose `--check` closed green at the end of this entry's own
workflow. Remediation is tracked as M8 (`AF-xa01k3`,
[docs/MILESTONES.md](MILESTONES.md)).

---
## 2026-09-01 — L0 is built: the kernel floor ships in the monitor

Supersedes one line of the 2026-08-28 stack entry below, which says "L0 is
recommended and unbuilt." L0 is built: the Landlock kernel floor enacted by
the monitor (`crates/af-monitor/src/landlock.rs`, the ML milestone) denies
filesystem writes outside the granted trees and scopes signals before the
first program runs, with no supervisor in the loop. It answers 6 of the 68
questions the pack can ask (160 rules, counted 2026-09-01 after the
audit-trail rules of M8) and backs 3 of the 9 `deny` rules, and
`research/spikes/landlock/tests/count-rules.py` holds that count and fails
when the pack and the floor drift apart. The floor is a boundary for
filesystem rights and signals only — it holds no network right, and it is a
boundary, not a sensor. L3 still waits for the enterprise edition
([DIRECTION.md](DIRECTION.md) §10).

---
## 2026-08-31 — Correlation ships post-hoc, and the budget refused the write comparison

The M5 gate measured the correlation engine
(`agent-firewall correlate`) on the seeded discrepancy techniques and on
the benign corpus, in all three filter modes:

* **The engine judges recorded pairs, not live sessions.** The monitor
  holds processes at its boundaries; correlation reads two finished views
  and writes findings as `discrepancy` events that `replay` judges with
  the current rules. Live judging joins the monitor loop only with the
  alpha of M6, if at all — the post-hoc form already answers the
  milestone's question.
* **Two rules quarantine; one reports.** `correlation.sensor.silent-subtree`
  and `correlation.spawn.unreported` ship with `quarantine: true`, because
  the benign corpus exercised their negatives (every instance of every
  corpus run beat at about 1 Hz; every dynamic child registered after its
  exec) and fired zero in all three modes.
  `correlation.action.contradicted` reports, because the corpus is offline
  and cannot prove the negative for a connection.
* **The write-open comparison is refused, with numbers.** Comparing every
  held write open against the sensor's reports fired **30 times on one
  28-second corpus session** (write-only; 49 counting all-opens): `mkstemp`
  and other glibc-internal opens, retried lock attempts and reflog
  re-opens never cross the interposed libc, and bash probes `/dev/tty`
  with a write open that fails under a pipe. A rule on that comparison
  fires on shapes normal tools make, which the 2026-08-31 budget decision
  forbids whatever the severity. The comparison stays measurable behind
  `correlate --compare-write-opens` as research telemetry.
* **A frozen tracee is the monitor's own defense.** The wait loop continues
  a tracee that stopped itself, so a whole-process `SIGSTOP` cannot hold a
  session open — measured: the frozen child exits at the freeze instant.
  The silence fact stays reachable through the blinded shape (the sensor's
  descriptors closed mid-run), which raises the silence and the
  contradiction together.

Evidence: `research/bypass/correlate.sh`, `research/bypass/FINDINGS.md`
(After M5), `policies/correlation.yaml` (the tests of every rule).

---

## 2026-08-31 — The budget outranks the severity, measured on the detach

The first shipped form of the M4 detach rule quarantined: a descendant that
left the session tree suspended everything and asked. The benign corpus of
M1 refused it in the same run — `git maintenance run --auto --quiet
--detach`, which `git init` and `git commit` start on every normal session,
raises exactly that fact. The rule now reports and never asks
(`tamper.process.detached`, decision `allow`), and so does the outlived
liveness fact.

* **Binding for later work:** a tamper or correlation rule that fires on a
  shape a normal tool makes is wrong, whatever its severity. The kill of
  the monitor, the killed program that came back and the stripped sensor
  preload keep their quarantine, because each keys on an act that only an
  attacker performs: nobody signals the monitor by accident, nothing
  respawns a program the firewall just killed, and no tool removes the
  sensor preload.
* **The quarantine is not a severity level.** It is the most expensive
  question there is and needs its own negative test per rule, in the rule
  file and on the corpus.

Evidence: `research/bypass/FINDINGS.md` (After M4),
`research/bypass/results/benign-write-only/` (the git-maintenance detach in
the corpus trace), `policies/tamper.yaml` (the tests of every rule).

---

## 2026-08-30 — Correlation and tamper signals obey the interruption budget

A tightening of the direction adopted earlier the same day
([DIRECTION.md](DIRECTION.md) §3.4, §6):

* **Keyed to the firewall's own identity.** A tamper or correlation rule
  fires on the state of what the firewall itself installed — the monitor
  process, the session root, this session's sensor instances (requirement
  B.5 of [DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md)). "No
  in-process sensor on a foreign process" is never a signal: static binaries
  and raw `syscall()` are normal in a developer toolchain, and a rule that
  fires on them fires all day.
* **The budget applies to high severity too.** A tamper or correlation rule
  ships only with a negative test proving that a normal session — static
  binaries included — produces no question and no quarantine.

Evidence: the preload-sensor gap is measured in
[DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §1 (static binaries, raw
`syscall()`); the budget is [PRODUCT.md](PRODUCT.md) §5. Rationale: a
quarantine-first response is the most expensive question there is. It earns
its cost only when it is nearly never wrong.

## 2026-08-30 — Telemetry is opt-in, never a condition

The tension between DIRECTION.md §7 ("free but agree to telemetry") and §10
("optional, consented") is settled in favor of opt-in. Telemetry is never a
condition of the free edition: the firewall is fully functional with
telemetry off, consent is granular and revocable, and a sample's content is
inspectable before it is sent.

The research loop does not depend on client telemetry to start:
`research/threats/` bootstraps the corpus from public incidents, which is
how the corpus exists before the first consenting user. Rationale: the
audience most likely to install a security monitor is the audience most
likely to refuse telemetry. A moat that requires shipping against the
product's own values ([PRODUCT.md](PRODUCT.md) §3) is not a moat.

## 2026-08-30 — Direction update: cross-platform sensor architecture

Adopted the direction update. **[DIRECTION.md](DIRECTION.md) is the direction
of record** for the whole project. In brief:

* The product is a **cross-platform security and observability layer for AI
  coding agents**, vendor-neutral, watching the agent's whole execution tree
  from inside **and** outside the agent process.
* **Defense in depth**: several sensors, deliberately over-collecting
  telemetry at first, so evidence — not preference — picks the enforcement
  architecture.
* **In-process instrumentation is a sensor, never a boundary.** `LD_PRELOAD`
  (Linux) and API hooking (Windows) are re-admitted for semantic visibility.
  This does not overturn the 2026-08-28 rejection below: it was and stays a
  rejection *as an enforcement mechanism*. The new correlation principle
  (expected observation ≠ externally observed behavior is itself a signal)
  turns its weakness into detection.
* **Tamper detection is a first-class, high-severity signal.** Response:
  detect → suspend/quarantine → evidence → user decides (allow once /
  exception / terminate). Suspicious execution stops before it continues.
* **AI-controlled process identity** (`PROCESS_IS_AI_CONTROLLED`) propagates
  through the execution tree; a generic, extensible **agent detection
  subsystem** replaces reliance on executable names.
* **Early-access telemetry** is opt-in, disclosed, and redacted by design;
  the **research pipeline** turns quarantined events into detections —
  research agents never publish production rules directly.
* **Open/commercial boundary fixed**: infrastructure open (sensors,
  interception, process tracking, event schema, policy engine, local UI/CLI,
  quarantine, plugins, basic rules, integration APIs); intelligence private
  (corpus, research agents, signatures, feeds, threat intel). The moat is the
  loop: telemetry → research → detections → deployed protection → telemetry.
* **Developer edition first** (no root where practical, explicit control,
  quarantine + approval, optional telemetry); enterprise adds privileged,
  centrally managed enforcement later, with the principle: *an AI-controlled
  process must not continue if security visibility is lost.*
* **Immediate direction**: the learning plan of DIRECTION.md §11 — ten
  questions, eight workstreams, bypass harness included. Optimizing for
  learning over premature hardening.

Supersedes: any statement, anywhere in the repository, that Linux-only
`ptrace`+`seccomp` is *the* enforcement architecture; that in-process
instrumentation is out of scope; or that the repository's proof of concept is
the product's scope.

---

## 2026-08-28 — Four-layer mechanism stack, and the soundness rule

[DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §2 and §4, measured:

* **A decision that reads a path from the memory of the judged program is not
  sound.** A second thread changed the path the kernel used **47.6%** of the
  time. Refusals held 2000 of 2000 times.
* **The rule: decide on an object, never on a pointer into the memory of the
  program you are judging.** Exec interception, Landlock, and file
  descriptors are sound for this reason.
* The stack: **L0** Landlock (make the question unnecessary), **L1** seccomp
  `RET_TRACE` (hold and ask), **L2** exec ptrace (provenance and
  explanation), **L3** fanotify/eBPF (optional, privileged, enterprise).

L1 and L2 shipped on 2026-08-28–29 ([ARCHITECTURE.md](ARCHITECTURE.md) §3a);
L0 is recommended and unbuilt; L3 waits for the enterprise edition
([DIRECTION.md](DIRECTION.md) §10).

## 2026-08-28 — Rejected mechanisms

[DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §1 and §5, measured. Out, with
the reason:

* `LD_PRELOAD` as **enforcement** — defeated by `env -u LD_PRELOAD`; misses
  static binaries and raw `syscall()`. *(Re-admitted as a **sensor** by the
  2026-08-30 direction update; not as a boundary.)*
* `/proc` polling — missed 99.7% of processes at a 10 ms period.
* Full `PTRACE_SYSCALL` — 6.4× on file work; the filtered alternative costs
  1.3×.
* `seccomp USER_NOTIF` as the main path — must emulate every allowed call;
  `RET_TRACE` keeps the event model.
* Trapping `write` for content — 8.1× on a `dd` workload
  ([DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md) §A.2).

## 2026-08-28 — Session memory before more kernel mechanism

[DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md) §4: 20 of 147 then-known
scenarios needed no new observable, only an engine that remembers — the
cheapest coverage available. Order: session memory, then `file_open` /
`network_connect` observables. Shipped the same week: marks, thresholds,
baselines ([POLICY.md](POLICY.md) §3). Still open from the same analysis:
session identity (B.5), liveness and teardown (B.6) — both feed tamper
detection under the 2026-08-30 direction.

## 2026-08-28 — Launch, not attach

[RESEARCH.md](RESEARCH.md) §3: `PTRACE_TRACEME` before `execve` cannot miss
the first exec; `PTRACE_ATTACH` always races and Yama can refuse it. Launch is
the reliable path. Attach-style observation of an already-running agent is a
job for the detection subsystem ([DIRECTION.md](DIRECTION.md) §5) and must be
measured before it is trusted.

## 2026-08-27 — User-space, no root, deterministic, local

The founding constraints, restated since in
[PRODUCT.md](PRODUCT.md) §3: local enforcement, deterministic decisions
(a model never decides allow/deny), user space before privileges, provenance
instead of inferred intent. The 2026-08-30 direction keeps all four for the
developer edition and scopes privileged components to the enterprise edition.
