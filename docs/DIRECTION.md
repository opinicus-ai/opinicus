# Direction of record

**Adopted 2026-08-30. This document is the current direction for the whole
project.** Where an older document conflicts with it, this document wins. The
settlements are logged in [DECISIONS.md](DECISIONS.md).

[ARCHITECTURE.md](ARCHITECTURE.md) describes what the repository really builds
today. This document says where the product goes. A plan that contradicts this
document is a wrong plan, whatever its source.

---

## 1. What the product is

The product is a **cross-platform security and observability layer for AI
coding agents**.

It has three properties that no older plan may drop:

* **Vendor-neutral.** The system does not depend on cooperation from a
  specific agent runtime. It observes and controls agent behavior from both
  **inside and outside the agent process**, and the outside view never rests
  on the agent's goodwill.
* **Execution-tree responsibility.** An AI agent is responsible for an
  execution tree, not for one command. The system collects rich behavioral
  information about the whole tree, detects suspicious actions, and
  intervenes before damage occurs.
* **Not a sandbox.** The objective is not to recreate a normal sandbox. The
  product understands what the agent is, attributes what its descendants do,
  and intervenes only where intervention is needed.

The initial focus is **developer and early-access use without root or admin
privileges, where practical**. The enterprise edition can later add
privileged, policy-enforced components (section 10).

---

## 2. Defense in depth

Do not design around one interception mechanism. The system starts with
several sensors, so that measurement — not preference — decides which
mechanisms provide useful and reliable coverage.

```text
                    AI Agent
                       │
              ┌────────▼────────┐
              │ In-process      │
              │ instrumentation │
              └────────┬────────┘
                       │
                 process creation
                       │
              ┌────────▼────────┐
              │ Child processes │
              │ + propagation   │
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
     Process       Filesystem     Network /
     monitor        monitor       other I/O
         │             │             │
         └─────────────┼─────────────┘
                       ▼
                 Event correlation
                       │
                       ▼
                  Policy engine
                       │
              ┌────────┴────────┐
              ▼                 ▼
            Allow         Quarantine/Pause
                                │
                         User decision
                       Allow / Kill / Rule
```

The first versions deliberately collect **more telemetry than the eventual
production system**. The purpose is to discover where reliable enforcement
boundaries actually exist. Premature hardening throws away exactly the data
that the decision needs.

---

## 3. The sensor stack

### 3.1 In-process instrumentation on Linux

Explore injecting instrumentation directly into coding-agent processes,
starting with `LD_PRELOAD`-based instrumentation.

Potential hooks:

* process creation / `exec*`
* file access
* dynamic loading
* network-related libc calls
* relevant IPC
* environment manipulation

Instrumentation propagates into descendants where possible. This gives
high-quality semantic information close to the agent — including context that
an outside observer cannot see, such as what a program is *about* to do and
what it feeds its children on standard input.

**In-process instrumentation is a high-value sensor, not ground truth.** Do
not treat `LD_PRELOAD` as a security boundary. Software can bypass libc, use
direct syscalls, remove the preload, modify its own process state, or
otherwise evade user-space hooks. This is consistent with
[DETECTION-RESEARCH.md](DETECTION-RESEARCH.md), which measured that
`env -u LD_PRELOAD` defeats the preload, that static binaries and raw
`syscall()` never touch it, and that it is no boundary. It was rejected as an
enforcement mechanism and it stays rejected for that job. The direction of
record re-admits it as a **sensor** — and its weakness becomes a detection
opportunity: a process that the outside view sees, but that carries no
preload, has answered a question by removing the instrument. See section 3.4.

Research further Linux mechanisms — `ptrace` facilities, `seccomp`
facilities, process observation, and other user-space-compatible mechanisms —
preferring approaches that need no root for the initial product.

### 3.2 The Windows equivalent

Investigate Windows user-space instrumentation using API hooking and
trampolines, at the Win32 layer and at the lower `ntdll` paths.

Assume that sufficiently capable code can detect hooks, restore original
instructions, bypass higher-level APIs, manipulate injected modules, and
spawn processes designed to escape instrumentation. Windows hooks therefore
follow the same principle:

> **Hooks provide semantic visibility. Independent observation provides
> assurance.**

Later enterprise versions can use stronger OS-integrated mechanisms
(privileged services, kernel-adjunct telemetry). They are out of scope for
the developer edition.

### 3.3 External observation — what ships today

The Linux PoC already implements two external sensors and has measured two
more:

| sensor | state | evidence |
| --- | --- | --- |
| exec `ptrace` — provenance, hold-at-exec | ships | [ARCHITECTURE.md](ARCHITECTURE.md) §3, [RESEARCH.md](RESEARCH.md) |
| `seccomp` `RET_TRACE` filter — file opens, connections | ships | [ARCHITECTURE.md](ARCHITECTURE.md) §3a |
| Landlock — in-kernel "always no" rules | ships | [ARCHITECTURE.md](ARCHITECTURE.md) §3c |
| `fanotify` / eBPF — privileged tier | later, enterprise | [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §4 |

The measurements of [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) stand, and
the soundness rule stands with them: **decide on an object, never on a
pointer into the memory of the program you are judging.**

### 3.4 Semantic observation versus security assurance

Separate the two, and correlate them.

```text
In-process sensor:
"I am about to execute psql with these arguments and this stdin."

External observer:
"A descendant actually executed psql and performed these operations."
```

Either view alone can be defeated. Correlated, they are stronger than either:

```text
expected observation != externally observed behavior
   → a suspicious event in its own right
```

What counts as a discrepancy, and what does not. The toolchain itself makes
"no in-process sensor seen" normal: a static binary and a raw `syscall()`
never touch the preload, and an ordinary session runs several such programs
(`kubectl`, `terraform`, most Go tooling). A missing sensor on a foreign
process is **not** a signal. The discrepancy is keyed to what the firewall
itself installed in this session — the sensor instances it owns (requirement
B.5 of [DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md)):

* a sensor the firewall installed goes quiet or disappears while its process
  lives on;
* a process that the in-process sensor reported spawning never appears in the
  external view, or appears there without the sensor's report;
* an action that the sensor reported is contradicted by what the external
  sensors observed.

The interruption budget of [PRODUCT.md](PRODUCT.md) §5 governs these signals
like any other. A tamper or correlation rule that cannot prove, with a
negative test, that a normal session full of static binaries fires nothing
does not ship.

---

## 4. AI-controlled process identity

The system carries a concept like:

```text
PROCESS_IS_AI_CONTROLLED
```

Once an AI-agent root process is identified, that identity propagates through
its execution tree:

```text
Claude / Codex / OpenCode / Pi
              │
              ▼
            shell
              │
       ┌──────┴──────┐
       ▼             ▼
     python          npm
       │              │
       ▼              ▼
   application      script
```

All descendants remain associated with the originating AI session unless
there is strong evidence otherwise. Events retain provenance:

> agent, session, process, parent, ancestry, executable, argv, cwd, relevant
> environment, stdin/context where available, file operations, network
> activity, timestamp, policy decision.

How much of this the schema carries today:

| provenance | state |
| --- | --- |
| session, process, parent, ancestry, executable, argv, cwd, filtered environment, timestamp, policy decision | carried today ([ARCHITECTURE.md](ARCHITECTURE.md) §1) |
| agent identity from a detector (section 5) | carried today — tagged at launch, propagated through the graph, stamped on every event ([ARCHITECTURE.md](ARCHITECTURE.md) §3b) |
| stdin/context beyond the exec-time snapshot | partial — script and stdin snapshots exist at exec ([RESEARCH.md](RESEARCH.md) §6) |
| file operations beyond open, network beyond connect | partial — no delete/rename, no connection content |

Provenance serves two consumers: policy evaluation at decision time, and
forensic analysis afterwards. Both get the same record, because the trace and
the live decision use one schema.

---

## 5. Generic AI-agent detection

Do not depend only on executable names such as `claude`, `codex`, or
`opencode`. Agents arrive through npm, pnpm, Bun, pip, uv, standalone
binaries, shell scripts, wrappers, development checkouts, and package systems
that do not exist yet.

Build an extensible **agent detection subsystem**. Signals, combined rather
than relied on singly:

* known executables;
* package metadata;
* package-manager installation information;
* dependency manifests;
* command-line patterns;
* known agent libraries;
* LLM API usage;
* characteristic environment variables;
* process behavior;
* repository-wide access patterns;
* repeated tool/shell invocation patterns.

Once detection confidence crosses the threshold, tag the root and propagate
the identity to descendants (section 4). Provide a **detector/plugin
interface**, so a new agent is a new detector and not a redesign of the core.

Detection also unlocks a mode the launcher cannot: observing an agent that
was **not** started by the firewall. Launch remains the reliable path
([RESEARCH.md](RESEARCH.md) §3); attach and in-place observation are jobs for
the detection subsystem, and each is measured before it is trusted.

---

## 6. Tamper detection is a security signal

There is effectively no legitimate reason for a normal coding agent to
deliberately disable its security monitor. Detect:

* removing hooks;
* unloading monitoring libraries;
* modifying monitoring code;
* removing required preload configuration;
* disabling tracing;
* escaping an observed execution tree;
* launching deliberately unobserved descendants;
* modifying the firewall's files or processes;
* disabling telemetry or policy components programmatically.

A tamper signal is **high severity**. The response is not an immediate kill:

```text
detect
   ↓
suspend/quarantine
   ↓
show evidence
   ↓
user chooses
   ├── allow once
   ├── create exception
   └── terminate
```

The property that matters: **suspicious execution stops before it can
continue.**

High severity does not exempt the detection from the interruption budget — a
quarantine is the most expensive question there is. A tamper rule keys on the
firewall's own identity — the monitor process, the session root, the sensor
instances this session installed — and never on the absence of
instrumentation on a foreign process, which normal toolchains produce every
day (section 3.4). Every tamper rule ships with a negative test: a normal
session, static binaries and all, fires nothing.

Two pieces of this exist today in fail-closed form: `PTRACE_O_EXITKILL` kills
the tree if the monitor dies, and a traced call with no monitor returns
`ENOSYS`, so a process breaks rather than going unobserved
([ARCHITECTURE.md](ARCHITECTURE.md) §4). What does not exist yet is the
sensing side: firewall-owned session identity (the requirement B.5 of
[DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md)), liveness and
teardown observation (B.6), and the quarantine flow as an interactive state.
The `evade` axis of `research/threats/` already catalogs the attacker side.

---

## 7. Early-access telemetry

The first release is explicitly **alpha/beta security software**. Users must
understand:

* false positives are expected;
* false negatives are possible;
* this is not yet a production security boundary;
* it must not be their sole protection;
* telemetry is important to improving detection.

Telemetry is strictly opt-in. It is never a condition of the free edition:
the firewall is fully functional with telemetry switched off, consent is
granular and revocable, and the content of a sample is inspectable before it
is sent. Suspicious-event samples are the payload: process tree,
executable hashes, argv, relevant stdin, file operations, relevant
environment, policy decisions, agent/session identity, and surrounding
behavioral events.

Security and privacy are part of the pipeline, because agent environments
routinely contain API keys, tokens, credentials, source code, proprietary
data, and PII. **Redaction and minimization are designed into the telemetry,
not bolted on.** The monitor already redacts environment values by pattern
([RESEARCH.md](RESEARCH.md) §4); that is the pattern, generalized.

Today nothing leaves the machine: traces are local JSON Lines. The telemetry
program is new work, and it ships only with the redaction design, the consent
flow, and the disclosure.

The research pipeline does not wait for telemetry. `research/threats/`
bootstraps the corpus from public incidents, which is how the loop
(section 8) runs before the first consenting user exists.

---

## 8. The suspicious-event research pipeline

Suspicious events optionally become research samples:

```text
Client detection
      │
      ▼
Quarantined event
      │
      ▼
Redaction / packaging
      │
      ▼
Research backend
      │
      ▼
Automated analysis agents
      │
      ▼
Candidate behavior/signature
      │
      ▼
Regression corpus
      │
      ▼
Human review
      │
      ▼
Published detection update
```

The analysis agents investigate: why something happened; whether it was a
real attack or a false positive; possible bypass techniques; similar known
techniques; deterministic detection strategies; better interception points;
regression tests; candidate policy and signature changes.

Governance rule, with no exceptions:

> **Research agents never directly publish production detection rules.**
> Candidate rules need deterministic tests, benchmarks, and human approval.

This pipeline is the industrialized form of what `research/threats/` does by
hand today: incident research, a ledger, scenarios with coverage judgments,
and rules derived under the interruption budget
([PRODUCT.md](PRODUCT.md) §5). The client telemetry of section 7 becomes its
input stream; `research/threats/` remains the methodology.

---

## 9. The open-source / commercial boundary

### Open source — the security/runtime infrastructure

Everything a user must be able to inspect and verify:

* sensors;
* interception infrastructure;
* process tracking;
* event schema;
* policy engine;
* local UI/CLI;
* quarantine mechanism;
* plugin interfaces;
* basic rules;
* integration APIs.

Transparency is the point: software with significant machine visibility must
be auditable by the people it runs on.

### Private/commercial — the intelligence

* telemetry corpus;
* attack samples;
* research infrastructure;
* automated research agents;
* proprietary detection knowledge;
* continuously updated signatures/rules;
* threat intelligence;
* behavioral models;
* curated rule feeds.

The long-term moat is not closed source code. It is the loop:

> **telemetry → research → detections → deployed protection → new telemetry**

The loop compounds with adoption. The repository license (Apache-2.0) covers
the infrastructure column and only that column.

---

## 10. Consumer versus enterprise architecture

### Developer / individual edition — the initial target

* no root/admin where possible;
* explicit user control;
* transparent behavior;
* local inspection;
* ability to disable protection;
* quarantine + interactive approval;
* optional, consented telemetry.

### Enterprise edition — later, additive

* privileged service;
* administrator-installed monitoring;
* centrally managed policies;
* Windows Group Policy / enterprise deployment;
* protection that ordinary users cannot disable;
* tamper protection;
* centrally distributed intelligence;
* centralized audit trail.

Enterprise policy may state:

> **An AI-controlled process must not continue if security visibility is
> lost.**

Under that policy, loss of instrumentation suspends the affected execution
tree. The developer edition already contains the fail-closed ancestors of
this principle (`PTRACE_O_EXITKILL`, `ENOSYS`-on-detach, section 6); the
enterprise edition makes it a managed guarantee instead of a crash behavior.

---

## 11. The learning plan — immediate engineering direction

For the first Linux prototype, optimize for **learning**, not premature
production hardening. Instrument several layers, generate traces, deliberately
attempt bypasses in a controlled test harness, and let the evidence choose the
eventual enforcement architecture. **Do not prematurely commit to one Linux
mechanism.**

The ten questions, with the evidence already in the repository:

| # | question | status | where |
| --- | --- | --- | --- |
| 1 | How reliably can we identify AI-agent root processes? | **answered at launch** — detector registry with 5 built-in detectors; precision 1.000, recall 0.957 on a synthetic fixture corpus (no real agent installed); attach-style observation stays open | [ARCHITECTURE.md](ARCHITECTURE.md) §3b, [research/detection/FINDINGS.md](../research/detection/FINDINGS.md); W3 |
| 2 | How reliably can AI provenance propagate through process trees? | **answered for launch sessions** — no gap, no race; the agent tag now propagates through the same graph, and a detached descendant is flagged `unlinked` (B.6) | [RESEARCH.md](RESEARCH.md) §2, [ARCHITECTURE.md](ARCHITECTURE.md) §3b; attach-mode propagation = open |
| 3 | What can `LD_PRELOAD` provide? | **answered as a sensor** — 11 of 14 gap cells moved to seen, 98 % semantic gain, ×1.13–×1.29 over the product, quiet and silent-free on the corpus; kept, never a boundary | [research/spikes/inprocess/FINDINGS.md](../research/spikes/inprocess/FINDINGS.md); W1 |
| 4 | What common execution paths bypass it? | **partly** — `env -u`, static binaries, raw `syscall()` known; full matrix missing | W2 |
| 5 | What complementary mechanisms work without root? | **answered** — exec ptrace, seccomp `RET_TRACE`, Landlock; all user-space | [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) |
| 6 | Can suspicious processes be suspended before their action completes? | **answered at the action level** — exec stop, syscall stop; quarantine as a lasting state = open | [RESEARCH.md](RESEARCH.md) §5; W6 |
| 7 | How reliably can tampering be detected? | **answered in part, launch sessions** — tamper facts sensed and quarantined (M4), expected-versus-observed discrepancies measured (M5): the silent-sensor and unreported-spawn rules ship quiet on the benign corpus, the write-open comparison was refused by the budget (30 firings on one normal session), the contradicted connection reports, and the reported-unseen spawn measured zero — the exec stop is a kernel guarantee | [ARCHITECTURE.md](ARCHITECTURE.md) §3d, §3e, `research/bypass/FINDINGS.md`; attach mode stays open |
| 8 | Which events provide useful security semantics versus noise? | **partly** — interruption budget, filter cost curves, 99.7% read share | [PRODUCT.md](PRODUCT.md) §5, [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) |
| 9 | How much context distinguishes legitimate coding from dangerous behavior? | **partly** — session memory proves half a chain is normal and a chain is not; identity/liveness context missing | [DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md) §3 |
| 10 | What telemetry can safely become reusable detection intelligence? | **open** — redaction exists per-feature; pipeline unbuilt | W7 |

The workstreams, and what each one is for:

| id | workstream | it answers | kind of work |
| --- | --- | --- | --- |
| **W1** | In-process sensor spike: an `LD_PRELOAD` shim that emits `af-core` events for exec, file, network, dynamic loading, and environment manipulation, propagating into descendants | 3, half of 7 | research spike under `research/` |
| **W2** | Bypass and tamper harness: controlled adversarial tests — `env -u`, static binaries, direct syscalls, unhooking, `setsid`/double-fork, unobserved descendants, monitor tampering — run against **every** sensor | 4, 7 | research harness; feeds the `evade` axis |
| **W3** | Agent detection subsystem: detector plugin interface, first detectors, confidence scoring, root tagging | 1 | pure software |
| **W4** | Identity propagation: `PROCESS_IS_AI_CONTROLLED` as session state, escape detection | 2 (outside launch) | pure software |
| **W5** | Correlation engine: expected-vs-observed comparison, discrepancy events in the schema, keyed to the firewall's own sensor instances | §3.4, 7 | software, needs W1 |
| **W6** | Quarantine flow: suspend a subtree as a lasting state, show evidence, record the user's ruling | 6, §6 | pure software |
| **W7** | Telemetry pipeline design: redaction-first packaging, consent, disclosure | 10, §7 | design + privacy review first |
| **W8** | Windows spike: survey user-space hooking (Win32, `ntdll` trampolines) and an external observer candidate | §3.2 | research spike |

Suggested order: **W1 + W2 together first** — they are the reason the
direction asks for several sensors, and every later decision cites their
output. **W3, W6** are pure software with no kernel risk and can run in
parallel. **W4, W5** build on W1. **W7** is design work that gates the first
alpha release. **W8** starts when the Linux learning loop is running.

The sequenced, gate-tracked form of this plan — the milestone ladder, the
exit gate each step must pass, and the current status — is
[MILESTONES.md](MILESTONES.md).

---

## 12. The product hypothesis

> **AI agents should be treated as identifiable security principals whose
> actions and descendants can be observed, attributed, constrained,
> quarantined, and audited independently of the agent vendor.**

That vendor-neutral enforcement layer — and the continuously improving
threat-intelligence loop behind it — is the differentiation from adding
another sandbox around a coding agent.

---

## 13. Document map

| document | it holds |
| --- | --- |
| [DIRECTION.md](DIRECTION.md) (this document) | the direction of record: product, sensors, identity, tamper, telemetry, pipeline, business split, learning plan |
| [PROJECT.md](../PROJECT.md) | the idea, the principles, the architecture concept, the policy model, the risks |
| [PRODUCT.md](PRODUCT.md) | why the constraints are not optional, the interruption budget, what kills the product |
| [ARCHITECTURE.md](ARCHITECTURE.md) | what is really built: layers, boundaries, their limits |
| [RESEARCH.md](RESEARCH.md) | measured answers to the original Linux research questions |
| [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) | measured comparison of interception mechanisms; the four-layer recommendation |
| [DETECTION-REQUIREMENTS.md](DETECTION-REQUIREMENTS.md) | observables and memory the threat catalogue demands |
| [POLICY.md](POLICY.md) | the rule format and the built-in pack |
| [DECISIONS.md](DECISIONS.md) | dated decisions; the newest entry wins |
| [MILESTONES.md](MILESTONES.md) | the execution plan: the milestone ladder, the exit gates, the current status |
| `research/` (see `research/README.md`) | spikes, the benchmark, the threat catalogue and ledger |
