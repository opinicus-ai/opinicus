# Detection research: how the firewall should watch

`docs/RESEARCH.md` answers the questions of `PROJECT.md` section 10 for the
`ptrace` monitor that ships today. This document answers the question that
came after it:

> The firewall stops a dangerous **program**. It does not stop a dangerous
> action inside a program that already runs. What should we do about that?

Four research threads measured the candidate mechanisms on one machine with
one shared benchmark. This document holds the result and the recommendation.

> **Direction update, 2026-08-30.** The measurements here stand unchanged.
> [DIRECTION.md](DIRECTION.md) changes one classification: this document
> rejected `LD_PRELOAD` as an **enforcement boundary**, and that rejection
> holds — `env -u LD_PRELOAD` is still one word. The direction of record
> re-admits in-process instrumentation as a **sensor** for semantic
> visibility, under the rule that a sensor is never the decider and that its
> silence or removal is itself a signal, caught by correlating the in-process
> view with the external sensors ([DIRECTION.md](DIRECTION.md) §3.1, §3.4).
> The Windows hooking track follows the same rule: hooks provide semantic
> visibility, independent observation provides assurance. Where this document
> says a mechanism is "out", read "out as a boundary"; the sensor question is
> a new experiment, tracked as workstream W1 in DIRECTION.md §11.

Everything below was measured on Fedora 43, kernel 7.0.9, `x86_64`, as a
normal user with no root and no capability. The spikes are in
`research/spikes/`, and each one keeps its own `FINDINGS.md` with the raw
numbers and the code.

---

## 1. The result in one table

The benchmark is `research/bench/bench.sh`. W1 makes 300 processes, W2 opens
many files, W3 mixes both. Lower is better. The baseline is the same workload
with no monitor.

| Mechanism | W1 exec | W2 file | W3 mixed | Can it stop an action? | Sound? |
| --- | --- | --- | --- | --- | --- |
| **Landlock** | 1.0× | 1.0× | 1.0× | yes, in the kernel | **yes** |
| **exec `ptrace`** (ships today) | 1.1× | 1.3× | 1.2× | yes, at the exec stop | **yes** |
| **`seccomp` `RET_TRACE`** | 1.2× | 1.3× | 1.3× | yes, at a syscall stop | **only for scalars** |
| **`seccomp` `USER_NOTIF`** | 1.1× | 1.5× | 1.4× | yes, it refuses the call | **only with a file descriptor** |
| full `PTRACE_SYSCALL` | 2.2× | 6.4× | 2.6× | yes | only for scalars |
| `LD_PRELOAD` | ~1.0× | ~1.0× | ~1.0× | yes, but advisory | **no** |
| `/proc` polling | ~1.0× | ~1.0× | ~1.0× | **no** | **no** |

Two mechanisms are out at once:

* **`/proc` polling missed 99.7% of the processes** in W1, at every period
  down to 10 ms. It learns about a process only after that process ran. It is
  telemetry, not a control point.
* **`LD_PRELOAD` is defeated by `env -u LD_PRELOAD`**, which is one word. It
  also misses a static binary and a raw `syscall()`. It is a debugging tool,
  not a security boundary.

---

## 2. The finding that matters most

The four threads converged on one result that nobody set out to look for.

**A security decision that reads a path out of the memory of the target is
not sound.**

The supervisor reads the path, decides, and lets the call continue. But the
kernel reads the path again when the call runs. Another thread of the same
program can change the memory in between. The `seccomp` thread measured this
directly: with two threads sharing one buffer, **the path the supervisor read
differed from the path the kernel used 47.6% of the time**. A refusal always
held, but an *allow* decision was wrong about half the time.

`SECCOMP_IOCTL_NOTIF_ID_VALID` does not help. It catches a target that died.
It reported nothing during the failing run.

`docs/PRODUCT.md` requires deterministic decisions. A path read this way is
not deterministic, so it cannot carry a rule.

### Three mechanisms are sound, for three different reasons

| Mechanism | Why it is sound |
| --- | --- |
| **exec interception** | `execve` destroys every other thread of the program. Measured: 5 threads before, 1 after. At the exec stop **no other thread exists** that could rewrite the command line. |
| **Landlock** | It never reads a path at decision time. The allowed paths are fixed in the kernel **before the program starts**. |
| **a file descriptor** | When the supervisor opens the file itself, or the kernel hands it an object rather than a user pointer, there is nothing to rewrite. Measured: **0 wrong in 6000** with a writer thread running. `fanotify` works this way. |

This is why the shipping exec boundary is worth keeping, and it is the rule
for every future mechanism: **decide on an object, never on a pointer into the
memory of the program you are judging.**

---

## 3. What we lose today

The gap is real and it is large. A single Python process, with the firewall
set to refuse everything:

```
agent-firewall run --approve deny --trace t.jsonl -- python3 inproc.py

{"tree_gone": true, "file_gone": true, "tcp": "data", "new_programs": 0}
firewall exit=0

trace: 1 process_exec, 1 process_fork, 2 process_exit, session start and end
       0 file events, 0 network events, 0 policy decisions
```

The process deleted a directory tree, deleted a file and opened a network
connection. The firewall was set to deny. It denied nothing, because it saw
nothing. No new program started, so no exec stop happened.

The same gap has a second, quieter cost. The rule pack holds **7 rules that
can never fire** on this monitor, because they need a file or network action
that the monitor does not make. They include `filesystem.credentials.read` and
`network.connect.production-host`. Until now `policy list` counted them with
the rest, so a user could believe a credential file was watched. The command
now marks them and names them.

---

## 4. The recommendation: four layers, not one mechanism

The threads started as a comparison and ended as a stack. Each layer answers a
different question.

```
L0  make it impossible   Landlock         1.0×    no question, no supervisor
L1  hold it and ask      seccomp TRACE    1.2×    the rules that need a decision
L2  record it            exec ptrace      1.2×    provenance and explanation
L3  optional, privileged fanotify, eBPF   --      for a company with an installer
```

### L0 — Landlock. Make the question unnecessary.

This layer matters more than its size suggests. `docs/PRODUCT.md` section 5
names the thing that kills the product: too many questions. A user who is
asked too often switches the protection off, and then the protection is zero.

Landlock removes the question completely. The kernel enforces the rule with no
supervisor in the loop, and the cost is **1.0×** — measured, not estimated.
Verified independently: a credential read two shells deep gives
`Permission denied` with no prompt and no measurable overhead.

It carries **10 of the 69 rules**, and all 10 are rules that stop the user
today. That removes **24% of the interruption budget**. This kernel gives ABI
8, so all filesystem rights and both TCP rights are available.

Its limits are hard and must be stated: it cannot ask, it cannot be relaxed
after it is applied, and it sees no program name, argument or SQL text. It
carries the rules whose answer is always no, and nothing else.

### L1 — `seccomp` `RET_TRACE`. Close the in-process gap.

This is the direct upgrade of the shipping monitor, not a replacement. The
filter selects which syscalls stop, so the kernel drops the boring traffic
before the supervisor wakes. That is the whole difference between 8.3× and
1.3×: **the mechanism is not the cost, the filter is.**

It keeps everything that already works — `PTRACE_EVENT_EXEC`, the fork
tracking, the provenance graph, `EXITKILL`. The filter survives `fork` and
`execve`, so one filter at the session root covers the whole process tree.
The policy engine needs **no change**: `EventKind::FileOpen`,
`NetworkConnect`, `Action::FileOpen` and `Action::NetworkConnect` already
exist in the schema and are the reason those 7 rules were written.

Choose `RET_TRACE` over `USER_NOTIF`. It keeps the existing event model, and
`USER_NOTIF` must emulate every allowed syscall itself, which is a large
amount of work and a source of bugs.

Apply the soundness rule from section 2: **use it to decide on the syscall
number and on scalar arguments, which held 2000 of 2000 times. Do not use a
path read from the target as the basis for an allow.**

### L2 — exec `ptrace`. Keep it.

It ships, it is sound, and it costs 0.042 ms per new process. It carries the
provenance chain that every explanation depends on, and the 28 report-only
rules. It also has a new job: when L0 refuses something, the developer sees a
bare `EACCES` with no reason. L2 can still observe the failing call and
explain it. **Without that explainer the first confused developer switches L0
off**, and the cheapest layer is the one we lose.

### L3 — the privileged tier. Optional, and later.

A product that needs root will not be installed, so nothing here may be
required. Two are worth building when a company accepts an installer:

* **`fanotify` with `FAN_OPEN_PERM`** — the only privileged path that can hold
  and ask, and its event carries a file descriptor to the kernel object rather
  than a user pointer, **so it does not have the race of section 2**.
* **eBPF tracepoints** — very cheap and very complete for provenance, but it
  blocks nothing.

Do not build on the `proc` connector. It needs `CAP_NET_ADMIN`, gives no
command line, cannot hold a process, and is worse than the `ptrace` we already
have.

---

## 5. What we are not doing, and why

| Rejected | Reason |
| --- | --- |
| Full `PTRACE_SYSCALL` | 6.4× on file work. The filter gives the same visibility for 1.3×. |
| `seccomp USER_NOTIF` as the main path | Must emulate every allowed call; loses the existing event model. |
| Any allow decision from a path in target memory | Wrong 47.6% of the time with two threads. |
| `LD_PRELOAD` | `env -u LD_PRELOAD` defeats it. |
| `/proc` polling | Missed 99.7% of processes at 10 ms. |
| Replacing exec `ptrace` | It is sound, cheap, and carries the provenance. |

---

## 6. Honest open items

* `no_new_privs` is required for `seccomp`, and it stops `sudo` from
  elevating. This looked like a blocker, but it is not a **new** one:
  `ptrace` alone already strips setuid. Measured: `passwd -S` gives 7 fields
  normally and 2 fields under the shipping monitor. The firewall must still
  print its own message when `sudo` fails, or the user will blame the wrong
  thing.
* A `ptrace` restart is not free. During detach a traced call can return
  `-ENOSYS`, so the target **breaks** rather than merely going unobserved.
  Restarting the firewall under a live agent needs design work.
* The target can see that it is monitored, through `TracerPid` and the
  `Seccomp` fields of `/proc/self/status`. An agent that behaves differently
  when watched would weaken behaviour monitoring. No current agent does this,
  so the risk is real but not yet active.
* `fanotify` fail-open or fail-closed behaviour when the listener dies is
  unsettled in the sources and must be tested before L3 is built.

---

## 7. Where the numbers come from

| Thread | Directory |
| --- | --- |
| Cheap mechanisms and their coverage gaps | `research/spikes/baselines/FINDINGS.md` |
| `seccomp` `RET_TRACE` hybrid and the cost curve | `research/spikes/seccomp-ptrace/FINDINGS.md` |
| `seccomp` user notification and argument reliability | `research/spikes/seccomp-unotify/FINDINGS.md` |
| Landlock and the privileged tier | `research/spikes/landlock/FINDINGS.md` |
| The shared benchmark | `research/bench/bench.sh` |

Every spike is runnable and re-runnable. The benchmark gives every run a time
limit, because a research wrapper that stops answering must fail the
measurement instead of stopping it for ever.
