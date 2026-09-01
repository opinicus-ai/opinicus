# Threat model — the alpha contract

This document is the security contract of the alpha as **measured**: what
the shipped system holds, what it only observes, what a determined program
bypasses, and what nobody has measured yet. It is written for a person who
is deciding whether to run `agent-firewall` and needs to know exactly what
protection they are getting.

The one-line statement, the same one the binary prints on every run
(`crates/af-cli/src/run.rs:42`):

> **Alpha release — not a production security boundary.**

The full sentence, in the direction the repository has adopted for itself
([PROJECT-REVIEW.md](PROJECT-REVIEW.md) §3.3, §5.5;
[MILESTONES.md](MILESTONES.md), remediation preamble):

> **A Linux launch wrapper for cooperative or accidental coding agents:
> provenance-attributed policy prompts, deterministic pre-call refusal at
> the exec and write/connect boundaries, a conservative Landlock floor, and
> replayable local evidence. Not a sandbox, not host EDR, and not
> protection against a hostile same-user process.**

Every claim below cites its source: a document section, a `FINDINGS.md`
with runnable code, or a code path. Nothing in this document is sourced
from [DIRECTION.md](DIRECTION.md) alone — direction is not evidence of what
ships. Where a sentence here and [ARCHITECTURE.md](ARCHITECTURE.md) §§1–7
ever disagree, the disagreement is a bug in one of the two documents.

---

## 1. Scope — who this is for and what it covers

**The adversary the alpha is built for is a cooperative or accidental
agent**: a normal tool doing normal work, whose dangerous action is a
mistake — a wrong path, a destructive flag, a migration script that ends in
`DROP DATABASE`. For that adversary the system provides real, measured
friction at true boundaries (§3).

**The adversary the alpha is not built for is a hostile program running
with the same user's privileges.** The monitor is an unprivileged,
same-user process; the target owns everything the monitor owns. Against
that adversary the system is an observer with named blind channels and an
attackable monitor (§5.1–5.3). No rule, sensor or identity detector
changes that; only a separate-identity or privileged supervisor, or
kernel-side enforcement, would ([MILESTONES.md](MILESTONES.md) M17,
conditional).

Scope limits, each of which narrows every claim in §3:

* **Launch mode only.** The firewall sees the tree of the command it
  started. It attaches to nothing that was already running
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4, "A process that started before
  the session"; [DECISIONS.md](DECISIONS.md), 2026-08-28 "Launch, not
  attach").
* **Tree-local.** Helpers, editors, browsers, user services, remote
  machines — anything outside the launched tree — are outside the firewall
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4, "Another window"). A second
  terminal is outside the boundary.
* **Linux, x86_64, unprivileged user space.** The syscall filter table is
  `x86_64`-only (`crates/af-monitor/src/seccomp.rs:336`); on another
  architecture, and for 32-bit programs on an `x86_64` machine, the
  firewall keeps the exec boundary alone and says so
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4). The Landlock floor needs a
  kernel that offers it; without it the session keeps the pre-floor
  behaviour and the monitor says so ([ARCHITECTURE.md](ARCHITECTURE.md)
  §3c.2).
* **Alpha rule pack.** 161 rules as of this writing — 84 allow (report
  only), 68 approval_required, 9 deny — counted with
  `agent-firewall policy list --json` and validated with `policy check`
  (161 valid, 0 warnings) and `policy test` (705 tests passed) on the
  working tree. False positives and false negatives are expected; the
  pack is young ([PRODUCT.md](PRODUCT.md) §5).
* **One host measured.** Every number in the repository comes from one
  Fedora 43 machine, kernel 7.0.9, `yama/ptrace_scope = 0`,
  `kernel.io_uring_disabled = 0` (`research/bypass/FINDINGS.md:5`). No
  claim has been replicated on a second machine ([MILESTONES.md](MILESTONES.md)
  M13).

## 2. The four lists

The contract is four epistemic states, kept strictly apart. A sentence
that moves an item from a lower list to a higher one without new evidence
is the single fastest way to spend this project's honesty asset
([PROJECT-REVIEW.md](PROJECT-REVIEW.md) §5, P0-5, kill criterion K3).

## 3. What the alpha guarantees

Each item is deterministic, measured, and re-runnable from the repository.

1. **A launched descendant is stopped at `execve` before its new program
   runs one instruction.** This is the product's hardest primitive: the
   kernel stops a traced child at the exec boundary, so a denied action
   never happens at all — the demonstration's fake `psql` writes no marker
   line for the denied statement ([ARCHITECTURE.md](ARCHITECTURE.md) §3,
   §4). The same boundary is clean beyond stdio: the root's `pre_exec`
   marks every descriptor above two close-on-exec, so a capability a
   launcher held open — a writable file, a connected socket, a `memfd` —
   never enters the session (measured: the hostile-launcher payload
   counted exactly stdio and every write answered `EBADF`, every filter
   mode; `research/bypass/inherit.sh`). Measured from the other side: a
   spawn that the external view never saw was **0 on both corpora** — no
   rule ships for `spawn_reported_unseen`
   because there is nothing to detect ([ARCHITECTURE.md](ARCHITECTURE.md)
   §3e.2).
2. **Selected system calls inside a running program are held before they
   execute, on x86_64.** Write-intent opens in the default mode, every
   open in `all-opens`, outgoing `connect`s, and the two `io_uring`
   calls — the call is stopped at
   the `seccomp` stop with `PTRACE_O_TRACESECCOMP`: no byte is written and
   no packet has left. The ring calls closed the measured zero-events
   gap as visibility: every `io_uring_setup` and `io_uring_enter` reaches
   the engine and the built-in rule `tamper.bypass.io-uring` reports it;
   refusing the road itself is a host requirement decided on measured
   numbers ([DECISIONS.md](DECISIONS.md), 2026-09-01). Which calls stop
   is decided **in the kernel on the call number and a scalar
   argument**, so no thread of the target can race the selection
   ([ARCHITECTURE.md](ARCHITECTURE.md)
   §3a.2–3a.3, §4). Cost, measured on the three harness workloads: 1.16×,
   1.33× and 1.22× of the workload's wall-clock time when the kernel can
   decide from the `flags` argument, and 1.92× on the file workload when
   every open must reach the monitor (`all-opens`)
   (`research/spikes/seccomp-ptrace/FINDINGS.md:11–13, 73–84`).
3. **The Landlock floor denies the named "always no" rule classes at
   kernel grade, before the first program runs.** Credential stores,
   system trees and raw devices under the floor's plan are impossible to
   reach for the whole session; the ruleset is immutable, survives
   `fork`/`exec`, and no approval can open it
   ([ARCHITECTURE.md](ARCHITECTURE.md) §3c.3). Measured: 0 of 6 escape
   attempts worked, a new user namespace included
   (`research/spikes/landlock/FINDINGS.md:19,233`), at a cost of
   0.98×–1.07× — zero within the noise
   (`research/spikes/landlock/FINDINGS.md:263–271`).
4. **Fail-closed on monitor loss.** If the monitor dies,
   `PTRACE_O_EXITKILL` kills the whole session tree — measured: an
   external `SIGKILL` to the monitor took the tree with it every time, in
   every filter mode (`research/bypass/FINDINGS.md`, "Fail-closed holds
   under attack"). A held call that arrives with no monitor returns
   `ENOSYS`: the program breaks rather than proceeding unobserved
   ([ARCHITECTURE.md](ARCHITECTURE.md) §4, "A restart of the firewall").
5. **Deny-safe approval.** Every abnormal approval path denies: the
   timeout (120 s by default, `crates/af-approval/src/terminal.rs:17`), an
   empty answer, three unknown answers, a closed terminal, no terminal
   ([ARCHITECTURE.md](ARCHITECTURE.md) §3.8;
   [PROJECT-REVIEW.md](PROJECT-REVIEW.md) §5.1).
6. **A scripted kill of the monitor by a session process is held before
   the signal runs.** The kernel filter holds `kill`, `tkill` and `tgkill`
   when the target is the monitor pid, and compares the pid in the kernel
   where nothing can race it (`crates/af-monitor/src/seccomp.rs:308–320`;
   [ARCHITECTURE.md](ARCHITECTURE.md) §3a.2, §3d.2). This is a **narrow
   scripted-kill defense, not monitor integrity** — see §5.2.
7. **Telemetry exfiltrates nothing, and no upload code exists.** The
   `af-telemetry` crate links no network library — its dependency graph is
   `af-core`, `serde`, `serde_json` and nothing else, re-runnable with
   `cargo tree -p af-telemetry` ([ARCHITECTURE.md](ARCHITECTURE.md) §3f).
   Since M10 (2026-09-01) the tree is enforced, not just described: the
   workspace-wide `deny.toml` bans the network-capable crates
   ([scripts/gate.sh](../scripts/gate.sh) and CI run `cargo deny check
   advisories bans licenses sources`), and
   [`crates/af-telemetry/tests/dependency_contract.rs`](../crates/af-telemetry/tests/dependency_contract.rs)
   pins the direct set and the shipped closure crate-by-crate, so
   `cargo test -p af-telemetry` fails on any dependency drift
   ([TELEMETRY.md](TELEMETRY.md) §4,
   [RELEASE.md](RELEASE.md)). Scope, stated honestly: both are
   dependency-graph checks; the runtime boundary is the Landlock floor,
   not this list.

## 4. What is advisory

Visible, honest, measured — and **not a control**. None of these items may
appear in a sentence about protection without this qualification.

1. **Paths read from the memory of the judged program.** The pathname and
   sockaddr arguments are read from tracee memory to *label* observations,
   denials and questions; they are **never the basis of an allow**. Measured
   under two threads: the supervisor's path differed from the kernel's
   **47.6%** of the time, while a refusal held 2000 of 2000 times
   ([DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §2, lines 71 and 219;
   the soundness rule, [ARCHITECTURE.md](ARCHITECTURE.md) §3a). A rule
   that allows on a pointer-derived path would be a soundness bug; if you
   find one, that is a security report (see [SECURITY.md](../SECURITY.md)).
2. **Agent identity.** A session tagged by the detector registry (noisy OR
   over five detector families, threshold 0.75) carries a *label*, not a
   principal. No shipped rule consumes the identity, and detection never
   decides an allow ([ARCHITECTURE.md](ARCHITECTURE.md) §3b.3, §3b.6).
   The corpus is synthetic — precision 1.000 / recall 0.957 on 53
   fixtures, no real agent installed ([ARCHITECTURE.md](ARCHITECTURE.md)
   §3b.3).
3. **In-process sensor facts.** The `LD_PRELOAD` sensor of
   `research/spikes/inprocess/` is a research instrument that reports —
   file deletes, renames, library loads, environment changes — and **never
   decides**. A sensor is not a boundary
   ([ARCHITECTURE.md](ARCHITECTURE.md) §8;
   [DIRECTION.md](DIRECTION.md) §3.4). No shipped rule matches sensor
   event kinds.
4. **Correlation findings.** The expected-versus-observed comparison runs
   **after the session**, on recorded traces; a discrepancy can name an
   act for the ruling that follows, but cannot stop the action that
   produced it ([ARCHITECTURE.md](ARCHITECTURE.md) §3e;
   [DECISIONS.md](DECISIONS.md), 2026-08-31).
5. **Tamper sensing beyond the scripted kill.** Signals toward the monitor
   through the held calls (§3.6), a detached descendant, a killed program
   that came back, a child with no sensor preload, and — since M8 — writes
   toward the firewall's own evidence files are sensed facts that rules
   judge ([ARCHITECTURE.md](ARCHITECTURE.md) §3d). They are tripwires on
   named shapes, not a guarantee of monitor or evidence integrity: the
   same-uid surfaces in §5.3 are not covered.

## 5. What is bypassable — structural, named, with evidence

These are known, open, and ride **with every protection claim** until
[MILESTONES.md](MILESTONES.md) M11 (`[af-12]`) measures or closes them.
Each carries its evidence line.

### 5.1 `io_uring` — held and reported; refusing the road is a host
requirement

The road itself was measured as a complete bypass: one `io_uring_enter`
performing `IORING_OP_OPENAT` with write intent produced **zero events in
every filter mode** — no `openat` syscall ever happened, the write through
the returned descriptor left no trace, and no rule could ever act on it
(`research/bypass/FINDINGS.md:86–92`, gap 1, scenario `evade-15`; measured
live on the reference host with `kernel.io_uring_disabled = 0`). Since
2026-09-01 the kernel filter holds `io_uring_setup` and `io_uring_enter`
at the call boundary in every mode that installs it, so no ring operation
crosses the filter unseen, and the built-in rule `tamper.bypass.io-uring`
reports every call.

**The deny was measured and refused on the numbers**
([DECISIONS.md](DECISIONS.md), 2026-09-01): with both calls answered
`EPERM`, nothing breaks — cargo, git, npm, venv+pip, tar and sqlite all
complete, and node falls back to its thread pool — but a normal node
session makes the calls on its own: **36 ring calls in one `npm ci` (27 in an
earlier identical run), 48 in one benign corpus run (36 earlier)**. A default deny therefore fires on everyday
work, which the interruption budget forbids whatever the severity
(PRODUCT.md §5). The enforcement posture is the host: set
`kernel.io_uring_disabled` to 2 and the kernel refuses the road at its
own grade, or load a local rule file that replaces
`tamper.bypass.io-uring` with a deny — the filter already holds the
calls, so that deny is complete before the ring performs anything
(`tests/e2e.sh` §U proves it end to end). `doctor` reports which posture
the machine is in.

What remains open, and rides with every ring-related claim:

* the road itself is open under the shipped rule: the report names every
  attempt, and only the host posture (sysctl or local deny) refuses it;
* a session with `--syscall-filter off` holds nothing, io_uring
  included;
* a ring the tree did not create — an inherited or handed-over
  descriptor — enters through the live-descriptor gap of §5.3, and only
  the held `enter` can judge its use;
* a 32-bit program carries another call table, and the filter lets its
  calls through rather than reading them wrongly (§1);
* a machine where the kernel refuses the filter keeps the exec boundary
  alone, and the monitor says so.

### 5.2 The monitor is a same-user process and is attackable

The monitor runs unprivileged, at the target's uid, with no privilege
separation and no `PR_SET_DUMPABLE` hardening. The seccomp filter holds
only `kill`/`tkill`/`tgkill` **when aimed at the monitor pid, from a
process of the session** (`crates/af-monitor/src/seccomp.rs:308–320`) —
the filter lives in the traced processes, so it binds nobody outside the
tree. The hostile same-UID harness of `[af-12]` measured every external
route under Yama 0–3 (`research/bypass/hostile.sh`; the matrix with every
errno is `research/bypass/FINDINGS.md`, “After M11-hostile”):

* **Yama 0 — nothing holds the memory routes.** `PTRACE_ATTACH` + `PTRACE_
  POKETEXT`, `process_vm_writev` and a write through `/proc/<pid>/mem`
  all succeeded against the live monitor, nothing sensed them, and the
  session ran to its normal end. A same-uid peer at scope 0 can rewrite
  the monitor. Accepted gap, pending the privileged tier (`[af-18]`).
* **Yama 1 — the kernel denies the memory routes** (`EPERM`/`EACCES`, and
  `EPERM` for `pidfd_getfd`). The denial is yama's: the firewall holds
  none of these routes and no event of it fires.
* **Yama 2/3 — the firewall cannot start.** The launch's pre-exec
  `PTRACE_TRACEME` answers `EPERM`; there is no session and no monitor to
  attack (measured, and isolated with a standalone program at scope 3).
* **Signals succeed at every scope that permits a session.** yama gates
  no signal: `pidfd_send_signal` (the documented unheld route,
  `seccomp.rs:43–44`) and an external `kill -KILL` both killed the
  monitor, and `PTRACE_O_EXITKILL` took the whole tree every time
  (§3.4) — fail-closed, **with no tamper event**: nothing of the firewall
  survives the kill to write one, and the missing `session_end` in the
  flushed trace is the only marker (`agent-firewall replay` names that
  shape after the fact).

No sentence may claim monitor integrity. The honest statement is: at
yama 0 the monitor is rewritable by the same user, at yama 1 the kernel
denies the memory routes for the monitor's sake and not the firewall's,
at yama 2/3 the product does not run, and the signal routes end the
session (fail-closed) without naming the killer.

Two smaller truths the harness fixed on the way: `doctor` presents yama 0
as a supported posture (`crates/af-monitor/src/caps.rs:189`) while the
memory routes are open there; and yama scope 3 is a **one-way** sysctl —
measured: `sudo sysctl -w` cannot lower it, not even for root — so a
machine taken to 3 stays there until reboot.

### 5.3 Live and inherited descriptors

The observation points are `open` and `connect`. Anything already open —
a socket, a file, a `memfd`, a pidfd — needs neither, and `write`,
`sendmsg`, `splice` and `sendfile` on it are outside the filter's held
set (`crates/af-monitor/src/seccomp.rs`, filter rules). Measured on
2026-09-01 by the inherited-descriptor gate
(`research/bypass/inherit.sh`, fixtures `inherit-fd.c` and
`inherit-scm.c`, `research/bypass/FINDINGS.md` "After M11-A"):

* **Closed at launch.** The monitor marks every descriptor beyond
  stdio close-on-exec in the root's `pre_exec`, as the last step before
  `execve` (`close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` in
  `crates/af-monitor/src/tracer.rs`). A hostile launcher that pre-opened
  a writable file, a connected socket, a `memfd` and a `pidfd` and exec'd
  the firewall itself delivered **no** capability: the session root
  counted exactly stdio and every write answered `EBADF`, in all three
  filter modes. This closure is the monitor's own — the earlier claim
  that Rust's `std::process::Command` closes inherited non-stdio
  descriptors was wrong: measured on the same machine, inherited
  non-CLOEXEC pipe descriptors survive into the exec'd child on both the
  `posix_spawn` and the `pre_exec` path, and the pre-hygiene binary
  leaked the file, the socket and the `memfd` (`fds=6`, writes landed,
  every mode; the `pidfd` of the same fixture is the control row —
  `pidfd_open` sets `FD_CLOEXEC` itself, so the kernel closed that one at
  exec with no help).
  The three descriptors that stay are standard input, output and error:
  the child keeps the terminal of the user. The capability probe of
  `doctor` gets the same hygiene
  (`crates/af-monitor/src/caps.rs`).
* **Open: in-tree inheritance.** A process of the tree that opens and
  connects itself produces both events — the opens are seen — but a
  forked descendant's `write` and `send` through the inherited descriptor
  leave **no event in any mode**, and the writes land. `write` is not in
  the held set (holding it was measured at 8.8× and rejected).
* **Open: `SCM_RIGHTS`.** A descriptor handed over a unix socket
  mid-run is installed in the receiver without `FD_CLOEXEC`; the
  receiver's use of it leaves no event in any mode, and the capability
  would even survive a later `exec` of the receiver — the launch hygiene
  arms only at the root's first `execve`.

The two open rows are named out-of-scope until a boundary tier exists
(`docs/DECISIONS.md`, 2026-09-01): closing them means either holding
`write` (the measured 8.8× price) or per-descriptor provenance
(`dup`/`SCM_RIGHTS` in the filter plus a descriptor table in the
monitor). Until one exists, **no sentence may claim coverage of a
capability the tree did not open during the session**.

### 5.4 The Landlock floor's exact scope

The floor mediates path-hierarchy rights only
([ARCHITECTURE.md](ARCHITECTURE.md) §3c, "What the floor carries, and what
it does not"):

* the work tree, `/tmp`, `/var/tmp` and `/var/cache` are fully writable
  (`crates/af-monitor/src/landlock.rs:358`), so a credential file created
  under the work tree or under `/tmp` is **not** protected by the home
  carve-out (`crates/af-monitor/src/landlock.rs:588–596`);
* no arguments, hostnames, SQL, `chmod` or ioctls; network rights are not
  handled at all; an `execve` from an anonymous file descriptor runs
  (measured, [ARCHITECTURE.md](ARCHITECTURE.md) §4);
* the ruleset is irrevocable per session — a legitimate need trains
  `--landlock off`, which removes the floor entirely.

### 5.5 The other named limits

Each of these is disclosed in [ARCHITECTURE.md](ARCHITECTURE.md) §4 and
[README.md](../README.md), "Does not work yet"; none may be quietly
dropped from a summary:

* **Content that leaves through an already-open connection.** The firewall
  sees the `connect`, never the protocol content; watching it was measured
  at 8.8× and rejected ([ARCHITECTURE.md](ARCHITECTURE.md) §4).
* **Delete and rename inside a granted tree.** The filter holds no
  `unlink`/`rename`; the floor makes deletes outside the granted trees
  impossible; inside them the delete is judged at the command that does it
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4).
* **Unlink of the firewall's own evidence.** A session process that
  unlinks the trace file — or removes a record from inside a running
  interpreter with no erase verb on any exec — is a measured gap
  (`research/bypass/evidence.sh`, rows b3 and d1;
  [ARCHITECTURE.md](ARCHITECTURE.md) §3d, "What the tamper layer does not
  cover").
* **A read-only open in the default mode** is invisible by design
  (`--syscall-filter all-opens` wakes it, at the measured price;
  [ARCHITECTURE.md](ARCHITECTURE.md) §3a, [README.md](../README.md)).
* **A program that knows it is watched.** `TracerPid` and `Seccomp` are
  visible in `/proc/self/status`; a hostile payload can run clean under
  observation and act when unobserved ([ARCHITECTURE.md](ARCHITECTURE.md)
  §4).
* **Standard input read from a pipe** stays invisible; the demonstration
  puts the dangerous statement in the command line for that reason
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4).
* **No agent log adapters** — the tool call of the agent is unknown to the
  firewall, which sees the process tree ([README.md](../README.md)).

## 6. What is unknown

Must not be converted into claims — positive or negative — until measured.

* **Kernel-version and distribution breadth.** Landlock ABI level,
  seccomp and io_uring behaviour, and Yama combinations beyond the one
  measured host ([PROJECT-REVIEW.md](PROJECT-REVIEW.md) §5.4;
  replication is [MILESTONES.md](MILESTONES.md) M13).
* **Rule quality on real development days.** The benign corpus is a
  scripted, synthetic session of git/cargo/npm work — not docker,
  terraform, venvs or node-gyp
  (`research/bypass/README.md`, `benign.sh`;
  [PROJECT-REVIEW.md](PROJECT-REVIEW.md) §6.2).
* **Real-agent identity precision and recall** — fixtures only
  ([ARCHITECTURE.md](ARCHITECTURE.md) §3b).
* **Hostile multithreaded races beyond the measured path case** — sockaddr
  races, `openat2` struct races, dirfd mutation
  ([DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §2;
  [PROJECT-REVIEW.md](PROJECT-REVIEW.md) §5.4).
* **Monitor restart and handoff semantics** under a live session
  ([ARCHITECTURE.md](ARCHITECTURE.md) §4).
* **Namespace transitions** and what they do to the floor and the trace
  ([PROJECT-REVIEW.md](PROJECT-REVIEW.md) §5.4).
* **Telemetry redaction under adversarial content** — the redaction
  matcher errs toward redaction, but adversarially shaped content is
  unmeasured ([TELEMETRY.md](TELEMETRY.md) §3;
  [MILESTONES.md](MILESTONES.md) M20).
* **Windows and macOS** — surveyed on paper only; "Nothing here was run"
  ([MILESTONES.md](MILESTONES.md) M7;
  [ARCHITECTURE.md](ARCHITECTURE.md) §8 table).

## 7. The interruption budget governs every rule

The product's kill criterion is not a missed attack; it is **too many
questions** ([PRODUCT.md](PRODUCT.md) §5). The contract with the user is
quiet: only an operation that destroys data or infrastructure with no
simple way back may stop the user, and recoverable operations only report.
Three mechanisms keep that promise honest:

* **Every rule change carries negative tests in the rule file and runs
  `cargo test -p af-policy`** ([POLICY.md](POLICY.md) §6). The in-file
  count stands at 700 passing tests as of this writing (measured with
  `agent-firewall policy test`).
* **The benign corpus must stay quiet.** `research/bypass/benign.sh` must
  run with zero questions, zero agent tags and zero quarantines; every
  run appends a line to `results/benign-summary.txt`, and a `FAIL` line
  anywhere in that ledger fails the gate
  (`research/bypass/README.md`, `benign-gate.sh`).
* **The budget outranks severity, and has measurably done so twice**: the
  git-maintenance detach rule (fires on every commit) and the write-open
  correlation comparison (30 firings on one 28-second benign session)
  were both refused with numbers
  ([DECISIONS.md](DECISIONS.md), 2026-08-31 entries).

The budget is why the guarantees in §3 hold their shape: the floor removes
questions by construction rather than asking them, and a fact that cannot
prove a quiet negative does not ship.

## 8. How to describe this project — the phrasing table

Adopted from [PROJECT-REVIEW.md](PROJECT-REVIEW.md) P0-5 and §14 A7. It
applies to every public sentence about this project: README, docs, commit
messages, advisories, issue replies, talks, landing pages. The project's
name is historical; it licenses nothing. One overclaiming sentence
contradicted by the repository's own bypass matrix spends the honesty
asset permanently (kill criterion K3, [PROJECT-REVIEW.md](PROJECT-REVIEW.md)
§15).

### Forbidden

| Phrase | Why it is forbidden | What is true instead |
| --- | --- | --- |
| "firewall-grade", "hardened perimeter" | The two decision boundaries are real, but the bypass set is measured open: live descriptors (§5.3), monitor attack surface (§5.2), and the residuals of the denied ring road (§5.1). | "Two decision boundaries — the exec stop and a held system call — plus a Landlock floor, with named and measured bypasses." |
| "sandbox" | The direction of record says the product is explicitly **not** a sandbox ([DIRECTION.md](DIRECTION.md) §1); the floor denies named path classes only (§5.4). | "A Linux launch wrapper / guardrail for cooperative or accidental agents." |
| "prevents exfiltration" | Content on an already-open connection is never seen (measured 8.8× and rejected); a ring the tree did not create enters through §5.3 and no protocol visibility exists (§5.1, §5.5). | "Holds the outgoing `connect`, the write-intent open and the `io_uring` calls at the call boundary, before the call runs." |
| "hostile-agent protection", "protects against malicious agents" | The monitor is a same-uid process the target can attack through unheld surfaces; no same-user boundary exists (§5.2). | "Not protection against a hostile same-user process; it is a guardrail for cooperative or accidental agents." |
| "kernel-enforced boundary" (unqualified) | Only the Landlock floor is kernel-enforced, and only for its named "always no" rule classes (§3.3, §5.4). The other boundaries are user-space `ptrace`/seccomp-notify. | "The Landlock floor enforces the named 'always no' rule classes in the kernel; the exec and syscall boundaries are unprivileged user-space mechanisms." |
| "the denial is certain" (of an event keyed on a path read from tracee memory) | Ruleset immutability guarantees the rules, not the path→prefix match: the event's path is read from the judged program's memory and differed from the kernel's 47.6% of the time under two threads (§4.1), so a trace can name a kernel denial for a call that then succeeds on the raced path. | "The refusal is certain for a call that really targets a denied path; the event is an explanation keyed on the tracee-supplied path, advisory under a race (§4.1)." |
| A one-workload number stated as a fact about builds or agents in general ("a read is 99.7% of a normal build") | The 99.7% is the synthetic W2 harness workload on the one measured host (§1, §6); no real build tree was ever measured. | "99.7% of the opens in the measured W2 file workload — a synthetic harness, one machine — were read-only." |

### Required qualifiers

| Where | Required |
| --- | --- |
| Any sentence about what the product does for security | "cooperative **or accidental** agents" — the protected adversary is a misfire, not a hostile peer (§1). |
| Any statement of product state | "alpha" — version 0.1.0, no releases, no signing; the banner the binary prints on every run is the minimum standard (`crates/af-cli/src/run.rs:42`). |
| Any protection claim | "not a production security boundary" rides with it — in the sentence or one sentence away. |
| Any file, network or tamper coverage claim | The named open bypasses ride with it, by name or by link to §5: **live/inherited descriptors, the same-user monitor attack surface, and the residuals of the denied ring road (§5.1)** — until M11 closes what remains. |
| Any cross-platform or architecture claim | "Linux; the syscall filter is x86_64-only" (§1). |
| Any number quoted from a measurement | Names what was measured — the workload or corpus (W1/W2/W3, the benign corpus, the threat catalogue) and the one-host scope (§1, §6) — and never generalizes it to "a normal build", "real agents" or field prevalence. |

### The honest one-liner

When one sentence is all there is room for, use this one (§0 above): a
Linux launch wrapper for cooperative or accidental coding agents —
deterministic pre-call refusal at the exec and write/connect boundaries, a
conservative Landlock floor, replayable local evidence; not a sandbox, not
host EDR, not protection against a hostile same-user process.

## 9. Claim → source index

| Claim in this document | Source |
| --- | --- |
| Exec stop before first instruction; denied action never runs | [ARCHITECTURE.md](ARCHITECTURE.md) §3, §4; `demo/run-demo.sh` marker file |
| `spawn_reported_unseen` 0/0, no rule ships | [ARCHITECTURE.md](ARCHITECTURE.md) §3e.2 |
| Held syscalls pre-execution; kernel-side selection on call number + scalar | [ARCHITECTURE.md](ARCHITECTURE.md) §3a.2, §3a.3 |
| Filter cost 1.16×–1.92× | `research/spikes/seccomp-ptrace/FINDINGS.md:73–84` |
| Floor kernel-grade, immutable, 0/6 escapes, 0.98×–1.07× | [ARCHITECTURE.md](ARCHITECTURE.md) §3c; `research/spikes/landlock/FINDINGS.md:19,233,263–271` |
| Fail-closed: EXITKILL kills tree every time/mode; ENOSYS without monitor | `research/bypass/FINDINGS.md` ("Fail-closed holds under attack"); [ARCHITECTURE.md](ARCHITECTURE.md) §4 |
| Deny-safe approval, 120 s default timeout | `crates/af-approval/src/terminal.rs:17`; [ARCHITECTURE.md](ARCHITECTURE.md) §3.8 |
| kill/tkill/tgkill-to-monitor held; pidfd_send_signal unheld | `crates/af-monitor/src/seccomp.rs:308–320`, `:43–44` |
| Telemetry: no upload code; tree pinned and enforced | `cargo tree -p af-telemetry`; [ARCHITECTURE.md](ARCHITECTURE.md) §3f; `deny.toml` + `crates/af-telemetry/tests/dependency_contract.rs` ([TELEMETRY.md](TELEMETRY.md) §4) |
| Path TOCTOU 47.6% wrong; refusal 2000/2000; never allow on a path | [DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §2 (lines 71, 219); [ARCHITECTURE.md](ARCHITECTURE.md) §3a |
| Identity: label not principal; no rule consumes it; synthetic corpus | [ARCHITECTURE.md](ARCHITECTURE.md) §3b.3, §3b.6 |
| Sensor reports, never decides | [ARCHITECTURE.md](ARCHITECTURE.md) §8; [DIRECTION.md](DIRECTION.md) §3.4 |
| Correlation is post-hoc | [ARCHITECTURE.md](ARCHITECTURE.md) §3e; [DECISIONS.md](DECISIONS.md) 2026-08-31 |
| io_uring: held at setup/enter, denied by the pack; the bare road was zero events in every mode | `crates/af-monitor/src/seccomp.rs` (filter rules); `policies/tamper.yaml` (`tamper.bypass.io-uring`); `research/bypass/FINDINGS.md` (gap 1, `evade-15`); [DECISIONS.md](DECISIONS.md) 2026-09-01 |
| Monitor same-uid attack surface: memory routes open at yama 0, kernel-denied at yama 1, no launch at 2/3; signals kill the monitor fail-closed at every scope, unsensed | `research/bypass/hostile.sh` + `results/hostile.md` (matrix in `research/bypass/FINDINGS.md`, “After M11-hostile”); `crates/af-monitor/src/seccomp.rs:308–320`; `crates/af-monitor/src/caps.rs:189`; [DECISIONS.md](DECISIONS.md) 2026-09-01 |
| Live/inherited descriptors: launch vector closed by `close_range` hygiene (measured); in-tree inheritance and `SCM_RIGHTS` open, out-of-scope until a boundary tier | `research/bypass/inherit.sh` + `results/inherit.md`; `crates/af-monitor/src/tracer.rs` (`close_beyond_stdio`); [DECISIONS.md](DECISIONS.md) 2026-09-01 |
| Floor's writable `/tmp` etc.; `.ssh` under `/tmp` unprotected | `crates/af-monitor/src/landlock.rs:358`, `:588–596` |
| x86_64-only filter; 32-bit exec-only with warning | `crates/af-monitor/src/seccomp.rs:336`; [ARCHITECTURE.md](ARCHITECTURE.md) §4 |
| Content of open connection unseen; 8.8× rejected | [ARCHITECTURE.md](ARCHITECTURE.md) §4 |
| Unlink of evidence files is a measured gap | `research/bypass/evidence.sh` rows b3, d1; [ARCHITECTURE.md](ARCHITECTURE.md) §3d |
| Interruption budget; two refusals with numbers | [PRODUCT.md](PRODUCT.md) §5; [DECISIONS.md](DECISIONS.md) 2026-08-31 |
| Rule counts 160 (83/68/9); 700 policy tests | Measured: `agent-firewall policy list --json`, `policy check policies`, `policy test` on this tree |
| Single-host evidence base | `research/bypass/FINDINGS.md:5`; [MILESTONES.md](MILESTONES.md) M13 |

This document is part of the M10 exit gate
([MILESTONES.md](MILESTONES.md)): two independent adversarial reviewers
must find no claim in it beyond the measured matrix. If code changes move
an item between §3, §4, §5 or §6, the change that moves it updates this
document in the same commit.
