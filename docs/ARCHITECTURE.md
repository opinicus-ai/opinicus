# Architecture

This document describes the Agent Firewall as the repository really builds
it. It names the crate of every layer. It shows the path of one `exec`
through the whole system. It states where the enforcement boundary sits, and
what the boundary cannot stop.

Read [DIRECTION.md](DIRECTION.md) for the direction of record and
[PROJECT.md](../PROJECT.md) for the idea and the plan. Read
[POLICY.md](POLICY.md) for the rule format.

## 1. The layers

The system has seven layers and one shared contract.

| Layer | Crate | Function |
| --- | --- | --- |
| Session launcher | `af-cli`, `af-monitor` | Makes the session, starts the command and keeps the root of the process tree. |
| OS event collector | `af-monitor` | Reads process events from the kernel with `ptrace`, holds a chosen system call with a `seccomp` filter, and reads facts from `/proc`. |
| Event normalization | `af-core`, `af-monitor` | Converts every platform event into one `Event` value. |
| Provenance engine | `af-provenance` | Builds the causal graph of the processes and answers ancestry questions. |
| Policy engine | `af-policy` | Matches deterministic rules against an action and returns a verdict, and what the session must remember. |
| Approval layer | `af-approval` | Asks the user, and remembers an answer for the session. |
| Recorder | `af-recorder` | Writes the events as JSON Lines and reads a trace again. |

The shared contract is `af-core`. It holds the event schema, the process
facts, the decisions and the traits between the layers. No layer depends on
a platform detail of another layer. Every layer communicates through the
types of `af-core`.

The most important types are:

* `Event` and `EventKind` — the normalized event.
* `ProcessInfo` — the facts of one process.
* `Action` — the thing that a rule evaluates.
* `Verdict`, `Decision` and `RiskLevel` — the answer of the policy engine.
* `SessionMemory` and `MemoryEffect` — what the session remembers, and what
  a rule asks it to write down. See section 6.
* `EventSink`, `PolicyEngine`, `ProvenanceView` and `Approver` — the traits
  that connect the layers.

## 2. The flow

```text
                            +---------------------------+
   you                      |  agent-firewall (af-cli)  |
   $ agent-firewall run --  |  reads options            |
     claude                 |  loads the policy files   |
                            +-------------+-------------+
                                          |
                                          v
+--------------------+       +---------------------------+
|  monitored tree    |       |  launcher (af-monitor)    |
|                    |       |  fork, PTRACE_TRACEME,    |
|  claude            |<------+  exec of the command,     |
|   -> bash          | trace |  seccomp filter install   |
|    -> migrate.sh   |       +-------------+-------------+
|     -> psql        |                     |
|                    |   kernel stops      |  raw stops: fork, clone,
+--------------------+   the process       |  exec, exit, signal, and
                                           |  a held open or connect
                                           v
                            +---------------------------+
                            |  collector (af-monitor)   |
                            |  reads registers          |
                            |  reads the tracee memory  |
                            |  reads /proc/<pid>/...    |
                            +-------------+-------------+
                                          |  Event (af-core)
                        +-----------------+-----------------+
                        |                 |                 |
                        v                 v                 v
            +-----------------+ +------------------+ +----------------+
            |  provenance     | |  policy engine   | |  recorder      |
            |  (af-provenance)| |  (af-policy)     | |  (af-recorder) |
            |  graph, ancestry| |  rules, verdict  | |  trace.jsonl   |
            +--------+--------+ +---------+--------+ +----------------+
                     |                    |
                     |  ancestry          |  Verdict
                     +---------+----------+
                               v
                    +---------------------------+
                    |  approval (af-approval)   |
                    |  shows the chain          |
                    |  asks on /dev/tty         |
                    +-------------+-------------+
                                  |
                                  v
                    allow  -> the kernel continues the exec or the call
                    deny   -> the exec fails, the process continues
                    refuse -> the call fails with EPERM, the process
                              continues
                    kill   -> the firewall ends the process tree
```

The monitored process waits during the whole decision. The decision path is
synchronous, local and deterministic.

## 3. The path of one exec

The migration script calls `psql`. The steps below happen between the call
and the first instruction of `psql`.

1. **The shell calls `execve`.** The process `migrate.sh` calls
   `execve("/usr/bin/psql", ["psql", "-c", "DROP DATABASE customer_prod"],
   envp)`.

2. **The kernel stops the process.** The monitor set `PTRACE_O_TRACEEXEC`
   and the fork options when the process started, so the kernel stops the
   process at the entry of the system call. The new program did not start.
   No instruction of `psql` ran.

3. **The collector reads the facts.** The collector reads the registers of
   the stopped process. It follows the argument pointers into the memory of
   the process and reads the program path and every argument. It reads
   `/proc/<pid>/cwd` and the parent identifier. The collector must read the
   arguments from the memory of the process, because `/proc/<pid>/cmdline`
   still holds the *old* program at this moment.

4. **The normalization layer makes an event.** The collector makes an
   `EventKind::ProcessExec` with a `ProcessInfo`, and an `Action::Exec` with
   the program name, the arguments, the working directory and the selected
   environment variables.

5. **The provenance engine answers the ancestry.** The graph keys every
   process on the pair of the process identifier and the start time, because
   Linux uses a process identifier again after a process ends. The engine
   returns the chain `psql -> migrate.sh -> bash -> agent-sim.sh -> session
   root`.

6. **The policy engine evaluates the action.** The engine gets an
   `EvalContext` with the session, the action, the process and the ancestry.
   A rule reads only these facts. The engine returns a `Verdict` with the
   strongest decision of all rules that matched. For the example above the
   rule `database.destructive.drop-database` returns
   `Decision::ApprovalRequired`.

7. **The recorder writes the decision.** The recorder appends an
   `EventKind::PolicyDecision` with the action, the verdict and the ancestry
   to the trace file.

8. **The approval layer asks the user.** The layer prints the chain, the
   operation, the rule and the risk. It reads the answer from `/dev/tty`, so
   it never takes the standard input of the agent. Without a terminal the
   layer uses the mode of `--approve`. After the timeout of
   `--approval-timeout` the layer answers with a deny.

9. **The monitor performs the answer.**

   * *Allow*: the monitor continues the process. The kernel completes the
     `execve`. The program starts.
   * *Deny*: the monitor writes an invalid system call number into the
     register of the stopped process. The `execve` therefore fails and
     returns an error to the shell. The shell continues, and the program
     never starts.
   * *Terminate*: the monitor kills the process tree of the session.

10. **The session ends.** The launcher writes an `EventKind::SessionEnd`
    with the exit code and the number of processes. The command returns the
    exit code of the child, or 3 when the firewall stopped an action.

## 3a. The path of one system call

The exec stop of section 3 cannot see what a program does **after** it
started. A single Python process can read a key, delete a tree and open a
connection without ever starting a second program.

A `seccomp` filter closes that. The steps below happen between the call of a
running program and the moment the kernel makes that call.

1. **The child installs the filter, one time.** In the same `pre_exec`
   closure where the child asks to be traced, and before its own `execve`, it
   promises `no_new_privs` and installs a small BPF program. A `seccomp`
   filter is inherited by every child and survives `execve`, so this one
   install covers the whole session tree. No descendant can escape it, and no
   descendant needs an install of its own.

2. **The kernel decides whether to hold the call.** The BPF program answers
   `SECCOMP_RET_TRACE` for `connect`, for `creat`, for `openat2`, and for
   `open` and `openat` when the `flags` argument carries a bit of
   `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`. Everything else runs with no
   supervisor in the loop. **That decision is made in the kernel on the call
   number and on a scalar, so nothing can race it.** `--syscall-filter
   all-opens` adds a second rule that holds every open.

   The filter never holds `execve`. The exec stop of section 3 already
   reports one, and a filter that held `execve` would break its own first
   `execve`: the trace action returns `ENOSYS` until the monitor has set
   `PTRACE_O_TRACESECCOMP`, which it can only do at a stop that the first
   `execve` must reach first.

3. **The monitor meets the stop.** `TRACE_OPTIONS` holds
   `PTRACE_O_TRACESECCOMP`, so the wait loop gets a `PTRACE_EVENT_SECCOMP`.
   The call has **not** happened: no byte is written and no packet has left.

4. **The collector reads the call.** It reads the registers with
   `PTRACE_GETREGSET`, takes the call number from `orig_rax` and the
   arguments from `rdi`, `rsi`, `rdx`, `r10`, `r8` and `r9`. It then reads
   the path or the socket address out of `/proc/<pid>/mem`. A relative path
   is joined with `/proc/<pid>/cwd`, or with `/proc/<pid>/fd/<dirfd>` when
   the call named a directory descriptor. `openat2` keeps its flags in a
   structure behind a pointer, so the collector reads them there.

5. **The action reaches the same engine as an exec.** The collector makes an
   `EventKind::FileOpen` or an `EventKind::NetworkConnect`, and an
   `Action::FileOpen` or `Action::NetworkConnect`. From here the path is the
   path of section 3: provenance, policy, session memory, recorder, approval.
   The policy engine needed no change for this; those actions were in the
   schema before anything produced them.

6. **The monitor performs the answer.**

   * *Allow*: the monitor continues the process, and the kernel makes the
     call.
   * *Refuse*: the monitor writes `-1` into `orig_rax` and `-EPERM` into
     `rax`, and continues. The kernel skips the call, and the program gets an
     ordinary permission error that it can handle and report in its own
     words. The value `-1` is load-bearing: any other number makes the kernel
     run the filter a second time.
   * *Terminate*: the monitor kills the process tree of the session.

   A refused call often comes back at once, because a program retries or
   walks a list of files. The launcher therefore answers one question for one
   rule and one action, and reuses that answer for the rest of the session.

### A path is sound to refuse with, and never to allow with

`docs/DETECTION-RESEARCH.md` section 2 measured this and it is binding.

The monitor reads the path at step 4, and the kernel reads the same memory
again when the call really runs. A second thread of the same program can
change it in between: measured, **the two differed 47.6% of the time**.

* A **refusal** holds, because the call never runs at all. Measured: 2000 of
  2000.
* A **report** and a **question to the user** are honest, because the worst
  case is a wrong name in a message.
* An **allow** that rests on the path is **not sound**. The firewall never
  makes one: a path that matches no rule is allowed because nothing matched,
  and not because the firewall trusted the path.

The consequence for a rule author: **a path-keyed exception on a `file_open`
rule is advisory.** It makes a normal program quiet. It does not hold against
a program that wants to defeat it. An exception that must hold has to name
something that cannot be rewritten — the call itself, a scalar argument, or a
fact of the process from the exec boundary.

## 4. The enforcement boundary

**The firewall has two enforcement boundaries: the entry of the `execve`
system call, and the `seccomp` stop of a held system call.**

The firewall is strong at the exec boundary:

* the new program did not run, so a denied action has no effect at all;
* the decision uses the real arguments of the real system call, and not a
  copy from the shell;
* the process cannot escape the tracer, and every descendant inherits the
  trace options;
* the demonstration proves the boundary: the fake `psql` client writes a
  line to a marker file at its first statement, and after a denied session
  the marker file holds no line for the dangerous statement.

It is strong at the system-call boundary for a different reason:

* the call did not happen, so a refused open writes no byte and a refused
  connect sends no packet;
* the choice of which calls stop is made in the kernel, on the call number
  and on a scalar argument, and no thread can change either;
* the filter is inherited by every child and survives `execve`, so one
  install at the session root covers the whole tree;
* `PTRACE_O_EXITKILL` still holds: a process that waits at a system-call stop
  dies with the rest of the tree when the firewall dies.

### What the boundaries cannot stop

* **Content that leaves through a connection that is already open.** The
  firewall sees the `connect`. The statement goes out later through `write`
  or `sendto` on the open socket. Holding those calls was measured at 8.8× on
  a chatty program, which is the same order as the full system-call tracing
  that this design rejected. Seeing that content needs a proxy for the
  protocol, not a system-call filter.
* **A delete and a rename.** The kernel filter could hold them. The
  normalized schema has the event kinds (`file_delete`, `file_rename`);
  only the in-process research sensor produces them today
  (`research/spikes/inprocess/`), and no shipped rule can act on them. A
  delete is still judged at the command that does it.
* **An open that only reads, in the default mode.** The kernel drops it, on
  purpose, because a read is 99.7% of the file traffic of a normal build.
  `--syscall-filter all-opens` holds it and costs more.
* **Content in a file.** A script can put a dangerous statement in a
  temporary file and give the file name to the program. The firewall sees
  the file name, not the content.
* **A restart of the firewall.** `SECCOMP_RET_TRACE` with no tracer does not
  mean allow; it means the call is skipped and returns `ENOSYS`. A program
  that runs while no firewall is there therefore **breaks** rather than going
  unobserved. `PTRACE_O_EXITKILL` covers the dangerous case by killing the
  tree, and restarting under a live session needs design work.
* **A program that knows it is watched.** The `TracerPid` and the `Seccomp`
  fields of `/proc/self/status` show both layers.
* **Anything with no system call.** Pure computation and memory writes stay
  invisible, as they do for every tool of this kind.
* **A machine that is not `x86_64`.** A call number is not the same on two
  architectures, so the filter table is not portable. The firewall reports it
  and keeps the exec boundary alone, rather than installing a wrong table.
* **A 32-bit program on an `x86_64` machine.** The same reason, one level
  down: an `i386` process uses another call table, and the filter allows
  every call whose `arch` field is not `AUDIT_ARCH_X86_64` rather than
  reading it with the wrong table. The exec boundary still holds such a
  program, but no file open and no connection **inside** it reaches the
  firewall. The monitor writes a `MonitorWarning` at the exec, once for each
  such process, so the gap is visible in the session and in the trace. It
  reads the class byte of the program file to see it.
* **A process that started before the session.** The firewall watches the
  tree of the command that it started. It attaches to nothing else.
* **Another window.** A user or an agent with a second terminal outside the
  session is outside the firewall.
* **A setuid program.** The kernel ignores the setuid bit of a program that
  a traced process starts. Such a program then behaves differently or fails.
  `no_new_privs`, which the kernel filter needs, takes the same thing away a
  second time; `--syscall-filter off` gives that half back and `ptrace` still
  takes the rest. The monitor writes a warning of its own when a session runs
  `sudo`, `su`, `passwd` or `pkexec`, so the user does not blame the program.
* **A time-of-check race.** A second thread of the same process can change
  the argument memory after the check and before the kernel copies it. This
  needs a hostile program, not a careless agent. It is why a path never
  carries an allow: see "A path is sound to refuse with, and never to allow
  with" in section 3a. A stronger boundary needs a mechanism that hands the
  firewall an object instead of a pointer, such as `fanotify`.
* **Performance under many processes.** Every stop costs time. The monitor
  therefore stops only for the events that it needs.

## 5. Trace and replay

The recorder writes one JSON object for each event, one object for each
line. The format is the normalized schema of `af-core`, so a trace from one
machine replays on another machine.

```console
$ agent-firewall run --trace session.jsonl -- bash ./migrate.sh
$ agent-firewall tree session.jsonl
$ agent-firewall replay session.jsonl --policy policies/
```

`replay` reads the recorded actions and evaluates them against the current
rules. A rule author can therefore test a new rule against a real session.
The end-to-end test uses `replay` for the same reason: it proves that the
rule of a live session also matches in a recorded session.

`replay` judges an exec, a file open and a network connection, in the order
of the trace and through the same memory-aware engine as a live session. Its
summary line counts each kind.

`--retention balanced`, the default, keeps a file open and a connection **that
at least one rule matched**, and drops the rest. A match of the level `info`
counts, so the mark of a credential read and the hits of a sweep both survive,
and a chain that the live session found is found again in the replay of the
default trace. An event that no rule matched cannot change a verdict, because
its verdict came from zero rules. Use `--retention all` to replay a rule that
did not yet exist when the trace was written.

A trace can hold command lines and paths of the user. Handle a trace like a
log file with private data. `.gitignore` therefore ignores `*.jsonl`.

## 6. Session memory

A rule about one action cannot say "a credential file was read, and now data
leaves the machine". `af-core::memory` holds the small store that carries such
a fact from one action to the next. It keeps three things:

| Part | What it holds | Which rule block reads it |
| --- | --- | --- |
| Marks | A name, the time, the subtree that set it, and a lifetime. | `marked` |
| Occurrences | The hits of one rule, with the value that makes a hit different. | `threshold` |
| Baseline | Named sets of text that the launcher read at session start. | `baseline_missing` |

### The flow of one effect

```text
   monitor                launcher (af-cli)             policy (af-policy)
   -------                -----------------             ------------------
   exec stop  ---------->  evaluate_with_memory  ---->   reads the memory
                           (&ctx, &memory)               matches every rule
                                  ^                             |
                                  |                             v
                           applies the effects  <-----  (verdict, effects)
                           memory.apply(e, ts)
```

**The engine never writes.** It returns a list of `MemoryEffect` values, and
the caller applies them, in event order, with `SessionMemory::apply`. Two
callers do this: `FirewallHandler` in a live session, and the `replay`
command for a recorded trace. Both run the same code path.

### The determinism rule

Two rules keep a replay equal to the live session:

1. **Event time, never the clock.** Every window and every lifetime is
   measured against the `ts` of the event that the monitor produced. The
   policy engine reads no clock, no network and no random number. The
   recorded event carries the same `ts`, so the replay computes the same
   windows.
2. **The caller applies the effects.** `evaluate` and `evaluate_with_memory`
   have no side effect. The order of the writes is therefore the order of the
   events, and not the order in which rules happen to run.
3. **The same actions, at the same time.** A live session judges an exec at
   the `ts` of the `ProcessExec` event, and it folds the content of standard
   input into that one verdict. The replay does the same: it takes the
   `StdinWrite` event that follows the exec of the same process into the same
   verdict, at the same `ts`. Neither side judges an action that the other
   one does not judge — with the two exceptions below.
4. **The root of the session is in the trace.** The launcher writes
   `root_pid` into the `SessionMeta` of the `SessionStart` event, and the
   replay reads it from there. A rule with the scope `subtree` needs it to
   tell one tool call from another. A trace with no `root_pid` — every trace
   that an older version wrote — makes `subtree` as wide as `session`, which
   is what such a trace already did when it was recorded.

Two things a trace cannot carry, so a replay judges less than the live session
did:

* **The text of a script.** The live session also reads the script that an
  interpreter runs. No event carries that text.
* **Standard input under `--retention balanced`.** The default level drops a
  `StdinWrite` event, so only a trace of `--retention all` replays the input.

The baseline follows the same rule. The launcher reads the git remotes of the
work tree one time, at session start, and puts them in the `SessionStart`
event inside `SessionMeta`. **A replay takes the baseline out of the trace and
never reads the machine again**, so a trace from another computer gives the
same verdicts here.

`agent-firewall replay <trace> --json`, run two times on one trace, gives two
equal outputs. A test in `crates/af-cli/tests/cli.rs` proves it.

## 7. Why this design

* **Deterministic first.** The decision path holds no model and no network
  call. The same trace always gives the same verdict.
* **Provenance instead of intent.** The firewall does not guess what the
  agent wants. It reports which process started which process.
* **User space first.** The firewall needs no kernel module, no container
  and no root account. A developer can try it in one minute.
* **One event schema.** A collector for macOS or Windows can replace
  `af-monitor` without a change in the other layers.

## 8. The direction: from one monitor to a sensor stack

The layers above are what ships. The [direction of record](DIRECTION.md)
widens the architecture around them, and the two must not be confused: this
document's sections 1–7 are **as built**, this section is **as directed**.

The target is defense in depth (DIRECTION.md §2): several sensors, correlated,
rather than one interception mechanism.

| sensor | state | what it adds |
| --- | --- | --- |
| exec `ptrace` | **ships** (§3) | provenance, hold-at-exec, session tree |
| `seccomp` `RET_TRACE` filter | **ships** (§3a) | file opens and connections inside a running program |
| in-process instrumentation (`LD_PRELOAD`) | **measured sensor** — spike of 2026-08-31 (`research/spikes/inprocess/`), not product-integrated | semantics close to the agent: about-to-exec, small-file content, delete/rename, dlopen, environment; durable instance registration for M4/M5; never a boundary |
| correlation of expected vs observed | planned | a discrepancy between the in-process view and this document's sensors is a high-severity signal on its own (DIRECTION.md §3.4) |
| Landlock | recommended, unbuilt | in-kernel "always no" rules; removes questions ([DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §4) |
| `fanotify` / eBPF | enterprise tier | privileged observation, later (DIRECTION.md §10) |
| Windows hooks (Win32/`ntdll`) | planned track | the Windows counterpart of the in-process sensor, under the same hook-visibility rule |

Three additions land in this architecture without changing sections 1–7:

* **Agent detection and identity.** A detector/plugin subsystem tags the
  session root as AI-controlled, and the identity propagates through the
  provenance graph that already exists (DIRECTION.md §4, §5). The graph keys
  processes on pid plus start time; the agent identity becomes one more fact
  the graph carries.
* **Tamper detection and quarantine.** The fail-closed behaviors that already
  exist — `PTRACE_O_EXITKILL`, the `ENOSYS` a traced call gets when no
  monitor answers — become sensed states with their own high-severity events,
  and the per-action approval flow of §3 grows a tree-level quarantine:
  suspend, show evidence, let the user rule (DIRECTION.md §6).
* **Event provenance for research.** The recorder of §5 already writes the
  normalized schema; the telemetry pipeline (DIRECTION.md §7) is a redacting
  packaging step in front of it, not a second event format.

The soundness rule of §3a binds every new sensor: **decide on an object,
never on a pointer into the memory of the program you are judging.** An
in-process sensor is exempt as a *reporter* — its reports are advisory input
to correlation — and never as a *decider*.
