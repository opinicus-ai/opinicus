# Decision log

Dated records of decisions that bind later work. Newest first. A decision
here overrides older prose in other documents until a newer entry says
otherwise. Each entry names its evidence.

---

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
