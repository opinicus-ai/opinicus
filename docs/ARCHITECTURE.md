# Architecture

This document describes the Agent Firewall as the repository really builds
it. It names the crate of every layer. It shows the path of one `exec`
through the whole system. It states where the enforcement boundary sits, and
what the boundary cannot stop.

Read [PROJECT.md](../PROJECT.md) for the idea and the plan. Read
[POLICY.md](POLICY.md) for the rule format.

## 1. The layers

The system has seven layers and one shared contract.

| Layer | Crate | Function |
| --- | --- | --- |
| Session launcher | `af-cli`, `af-monitor` | Makes the session, starts the command and keeps the root of the process tree. |
| OS event collector | `af-monitor` | Reads process events from the kernel with `ptrace` and reads facts from `/proc`. |
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
|  claude            |<------+  exec of the command      |
|   -> bash          | trace +-------------+-------------+
|    -> migrate.sh   |                     |
|     -> psql        |   kernel stops      |  raw stops: fork, clone,
+--------------------+   the process       |  exec, exit, signal
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
                    allow  -> the kernel continues the exec
                    deny   -> the exec fails, the process continues
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

## 4. The enforcement boundary

**The enforcement boundary is the entry of the `execve` system call of a
monitored process.**

The firewall is strong at this boundary:

* the new program did not run, so a denied action has no effect at all;
* the decision uses the real arguments of the real system call, and not a
  copy from the shell;
* the process cannot escape the tracer, and every descendant inherits the
  trace options;
* the demonstration proves the boundary: the fake `psql` client writes a
  line to a marker file at its first statement, and after a denied session
  the marker file holds no line for the dangerous statement.

### What the boundary cannot stop

* **An action inside a program that already runs.** The firewall reads the
  command line of `psql` at its start. A long database session that reads
  statements from a pipe after the start stays invisible.
* **A file write or a network connection.** The collector observes process
  events only. It does not observe `open` or `connect` yet. A rule for
  `~/.ssh` or for a production host is therefore not possible today.
* **Content in a file.** A script can put a dangerous statement in a
  temporary file and give the file name to the program. The firewall sees
  the file name, not the content.
* **A process that started before the session.** The firewall watches the
  tree of the command that it started. It attaches to nothing else.
* **Another window.** A user or an agent with a second terminal outside the
  session is outside the firewall.
* **A setuid program.** The kernel ignores the setuid bit of a program that
  a traced process starts. Such a program then behaves differently or fails.
* **A time-of-check race.** A second thread of the same process can change
  the argument memory after the check and before the kernel copies it. This
  needs a hostile program, not a careless agent. A stronger boundary needs
  `seccomp_unotify` or a kernel component.
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
