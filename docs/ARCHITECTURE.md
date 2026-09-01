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
| OS event collector | `af-monitor` | Reads process events from the kernel with `ptrace`, holds a chosen system call with a `seccomp` filter, enacts the Landlock kernel floor, and reads facts from `/proc`. |
| Event normalization | `af-core`, `af-monitor` | Converts every platform event into one `Event` value. |
| Provenance engine | `af-provenance` | Builds the causal graph of the processes, answers ancestry questions, and carries the agent identity of the session through the graph. |
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
* `Detector`, `DetectorRegistry`, `IdentifiedAgent` and `AgentTag` — the
  agent detection subsystem and the identity it produces. See section 3b.
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
   `SECCOMP_RET_TRACE` for `connect`, for `creat`, for `openat2`, for `kill`,
   `tkill` and `tgkill` when the target is the monitor itself (or every
   process, `kill(-1)`), and for `open` and `openat` when the `flags`
   argument carries a bit of `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`.
   Everything else runs with no supervisor in the loop. **That decision is
   made in the kernel on the call number and on a scalar, so nothing can
   race it.** `--syscall-filter all-opens` adds a second rule that holds
   every open.

   The signal rules are the tamper half of this layer (section 3d): the
   kernel compares the target identifier with the identifier of the monitor
   **before** the call runs, so a `SIGKILL` aimed at the firewall never
   happens unobserved. A signal to anything else is not held, which is why
   the rules cost a normal session nothing — no program signals the monitor
   unless it looked for it.

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

## 3b. The path of one identity

The firewall tags a session whose root command an agent detector identifies.
The tag is a fact of the session and of the provenance graph, and every event
carries it. The measurement behind this section is
`research/detection/FINDINGS.md`.

1. **The launcher assesses the root command, one time, at launch.** It
   resolves the program through `PATH`, reads the `package.json` of the
   working directory, and hands the facts — program, command line, working
   directory, inherited environment, manifest names — to the detector
   registry of `af-core::identity`.

2. **Five built-in detectors report weighted signals**: known executables
   (0.95; 0.60 for the ambiguous name `pi`), command-line patterns (runners
   and interpreters naming an agent package, 0.90), install layouts on the
   resolved executable path (0.85), dependency manifests (0.35 — supporting
   only, a project that develops *with* an agent depends on its package), and
   characteristic environment variables (0.90 for `CLAUDECODE=1`, 0.70 for a
   presence-only marker; an API key is never a marker).

3. **The registry combines, the threshold decides.** The combination is a
   noisy OR over the detectors — each detector contributes its strongest
   signal once, so a manifest naming five agent packages still cannot tag a
   build. At a combined confidence of 0.75 or more the session is tagged; the
   name, the confidence and every signal travel inside the `SessionStart`
   event, so a replay reads the identity from the trace and never detects
   again. Measured on the fixture corpus: precision 1.000, recall 0.957
   (23 agent and 30 non-agent fixtures; the one miss is the bare name `pi`).

4. **Every event of a tagged session carries the tag.** The handler of the
   launcher stamps `agent` on each event it records: the name, the confidence,
   and whether the process still links to the root.

5. **A descendant that detaches is flagged unlinked, never foreign.** Every
   process of a session shares the session identifier of the root until one
   of them calls `setsid`. The monitor reads that identifier from
   `/proc/<pid>/stat` at the exec stop and at the exit stop, the graph
   compares it with the root's, and a differing process is flagged with one
   `process_unlinked` event that carries the measured identifiers. The
   process keeps its recorded ancestry and its tag — the flag reports
   detachment, and never claims the process went unseen or belongs to
   somebody else. Measured: the setsid/double-fork fixture raises it at the
   re-exec and at the exit of the detaching parent, and the daemon that
   detaches and never runs another program raises it at its exit.

6. **No rule consumes the identity yet.** The scopes, the rules and the
   approval flow behave exactly as before; a rule that reads the tag is new
   rule work under the interruption budget. Detection itself never decides an
   allow: it reports, and the boundaries of sections 3 and 3a decide.

The detection runs at launch, from launcher facts. It does not watch a
process the firewall did not start — attach-style observation of a running
agent is future work, measured before it is trusted. A false agent tag is
worse than no tag, so every tie goes to quiet: a lone supporting signal — a
manifest, a presence-only marker — stays below the line. Measured on the
benign corpus of M1: zero questions and zero agent tags in all three filter
modes.

## 3c. The path of one kernel denial

The two boundaries of sections 3 and 3a hold a process **while the firewall
asks**. A third mechanism removes the question instead: before the first
program of the session runs, the child enacts a Landlock ruleset that makes
the "always no" rule classes of the built-in pack impossible, in the kernel,
with no supervisor in the loop. The measurement behind this section is
`research/spikes/landlock/FINDINGS.md` and the re-measurement of the pack
that ships with it.

1. **The monitor builds a plan, before the child exists.** From the working
   directory and the home directory it computes every grant: the work tree,
   `/tmp`, `/var/tmp` and `/var/cache` with every right; the entries of the
   home directory with every right except the credential stores; `/usr`,
   `/etc`, `/opt`, `/srv`, `/boot` with read and execute; `/proc`, `/sys`,
   `/run`, `/var` with read; the safe device files of `/dev`; nothing on the
   raw devices, the media trees and the credential stores themselves. The
   walk over the home directory happens here, in the monitor, so the child
   never reads a directory between `fork` and `execve`.

2. **The child enacts the plan.** In the same `pre_exec` closure where it
   asks to be traced, before the `seccomp` filter, it creates the ruleset,
   adds one rule per grant and calls `landlock_restrict_self`. The filter is
   installed after it, because the floor needs one file open per rule and
   the filter holds file opens. The child reports the fate of the enactment
   through one pipe byte; the monitor reads it after the first exec stop and
   tells the user when the floor is absent. A machine without Landlock, or a
   session with `--landlock off`, keeps exactly the behaviour of the
   versions before the floor existed.

3. **The ruleset is immutable for the session.** It survives `fork` and
   `execve`, no descendant can relax it, and no approval can open it. This
   is why only rule classes whose answer is **always no** ride on it: a rule
   where the user sometimes says yes keeps its question.

4. **The kernel answers, and the session explains.** When a rule class the
   floor carries matches, the session does not ask: the kernel refuses the
   action with `EACCES` whatever the user would answer, and the session says
   so. When a held file open targets a path the floor denies, the monitor
   reports a `kernel_denied` event that names the rule class — the denial is
   certain, because the ruleset was fixed before the program started, so the
   monitor explains it without waiting for the failed call. The rules the
   floor carries are named in a `kernel_floor` event at session start, and
   `research/spikes/landlock/tests/count-rules.py` keeps the list and the
   pack in step.

### What the floor carries, and what it does not

The pack holds 160 rules today; 77 stop the user. The floor answers 6 of the
68 questions the pack can ask (`filesystem.etc.write`,
`filesystem.delete.system-path`, `filesystem.delete.mount-root`,
`filesystem.credentials.write` on the paths it hides,
`filesystem.device.truncate`, `process.signal.kill-everything`) and backs 3
of the 9 `deny` rules with the same guarantee. Twenty-one classes are denied in
part and keep their question; 130 are blind to Landlock, which sees a path
and a TCP port and nothing else.

The floor is deliberately conservative about which questions it removes. A
class rides on the floor only when **no session shape** exists in which the
rule matches and the kernel still allows the action: a `.ssh` under the work
tree or under `/tmp` stays writable there, so `filesystem.credentials.write`
skips its question only for a path under a hidden store; a sweep over the
home directory cannot start in the common session and still can when the
work tree is the home itself, so `filesystem.find.delete-wide` keeps its
question. The negative test is the point: a question removed by mistake is
a question whose answer cannot take effect.

### The price

* `ls /` and `ls ~` fail with `EACCES`, because a directory that holds a
  hidden path gets no rule of its own (`ls ~/devel` still works). The
  carve-out enumerates the home directory once, at session start: 326 rules
  on the machine of the measurement, a build the spike timed at 1.0–1.7 ms
  for the same shape.
* The floor needs the `no_new_privs` promise that the filter needs, so a
  session with `--syscall-filter off` now also carries the promise. A
  session with both switched off keeps the right to raise a privilege,
  exactly as before.
* Landlock does not mediate `chmod` or ioctls, sees no program name, no
  argument and no host, and an `execve` from an anonymous file descriptor
  runs (measured). Network rights are not handled at all.

## 3d. The path of one tamper fact

The firewall senses an attempt against its own visibility, a rule judges
the fact, and a rule that asks for it suspends the whole tree until a
person rules. The measurement behind this section is
`research/bypass/tamper.sh` and the M4 section of
`research/bypass/FINDINGS.md`.

1. **The launcher names itself and its sensor.** The session metadata
   carries the process identifier of the monitor (`monitor_pid`) and, when a
   run carries the in-process sensor of `research/spikes/inprocess/`, the
   preload value and the instances that had registered at launch
   (`sensor`). These are the B.5 facts: what a tamper rule keys on is always
   a process of the firewall itself, never the absence of instrumentation on
   a foreign process.

2. **Four facts are sensed, each at the place that can measure it.**

   | fact | sensed by | sensed at |
   | --- | --- | --- |
   | a signal to the monitor | the kernel filter (§3a) | the system-call stop, before the call runs |
   | a descendant that left the tree | the provenance graph (§3b) | the event that reveals the differing session id |
   | a killed program that came back | the monitor | the exec stop of the same program under the same parent |
   | a child with no sensor preload | the launcher's facts and the exec environment | the exec stop |

   A fifth fact — a process that outlived the session root — is liveness,
   not tamper: the monitor reports it at the end of the session root.

3. **A rule judges every fact.** Each fact becomes an action of the schema
   (`signal_send`, `tamper` or `file_open`), reaches the same engine as an
   exec, and the rules of `policies/tamper.yaml` decide. Since M8 five
   audit-trail rules join them, measured by
   `research/bypass/evidence.sh`: a write-open of the session's own trace
   file quarantines (the launcher is the only writer of that file, so a
   refusal stops a truncation or a forgery before any evidence is lost);
   the sensor's two records, the rohrpost log and snapshot, and the agent
   transcript stores and shell histories are reports, because their honest
   writers live inside normal sessions — the sensor appends to its own
   records from every instrumented child (72 report firings, zero
   questions, on the sensor-active corpus), `rp` appends to the rohrpost
   log, and the agent harness appends to its transcript on every turn; an
   open cannot tell an append from a rewrite, so the budget wins. The
   erase of the rohrpost log by name (`rm`, `mv`, `shred`, `truncate`,
   `unlink`) is a question — no legitimate workflow erases the log. Of
   the tamper rules, five carry `quarantine: true`; the rest report,
   because a normal session makes the same shape: `git maintenance run
   --detach` detaches on every commit, and the corpus of M1 proved the
   question wrong — the interruption budget wins over the severity.

4. **A quarantine suspends the tree, shows the evidence and takes one
   ruling.** The monitor sends `SIGSTOP` to every process of the session and
   holds the group stops, the session prints the evidence chain, and the
   user answers once: allow once, an exception for the session, or the end
   of the tree. A refusal lets the call fail where a call exists — a signal
   to the monitor returns `EPERM` to the sender, and the monitor lives. The
   whole exchange is in the trace like any policy decision:
   `tamper`/`signal_send`, `policy_decision`, `quarantine_started`,
   `approval_requested`, `approval_resolved`, `quarantine_resolved`.

5. **The recorder writes the evidence through.** Every evidence event and
   every event that names a process of the session — the fork, the exec, the
   end — is flushed to the kernel as it happens. A monitor that an attack
   kills takes no cleanup path with it; the trace keeps what was recorded.
   Measured with the filter and the floor both off, where the `SIGKILL`
   succeeds: the trace of the killed monitor holds the `process_exec` of the
   attacker where M1 measured exactly one line.

### What the tamper layer does not cover

* A signal through `pidfd_send_signal` is not held: the kernel filter
  cannot follow a file descriptor. The floor's signal scope still refuses
  it on a machine that offers Landlock ABI 6.
* A signal to a whole process group is not held: the monitor shares its
  group with the session, so such a signal kills the sender too, and the
  command that shaped it is judged at the exec boundary.
* With `--syscall-filter off` no signal is sensed at all. The kernel floor
  still refuses a signal from the session to the monitor on a machine with
  Landlock ABI 6, and the durable recorder keeps the process events, but no
  tamper event exists in that mode.
* A killed program that comes back under a **different** parent is a new
  program, not a respawn: the fact keys on the pair of the parent and the
  executable, because a process identifier is gone once the process died.
* The sensor instance list is a snapshot from launch. Whether an instance
  still speaks is the correlation question of M5.
* An `unlink` of an evidence file reaches no rule: the kernel filter holds
  no `unlink` and no `rename` (§3a), so a session process that unlinks the
  trace file — or removes the rohrpost log from inside a running
  interpreter with no erase verb on any exec — is a measured gap
  (`research/bypass/evidence.sh`, rows b3 and d1). The unlink of the trace
  is the total-loss case: the recorder keeps writing to the unlinked
  inode, and the record dies when the monitor closes it.
* The evidence-path facts compare the absolute path string the launcher
  recorded. A session that reaches the same file through a symlink, a bind
  mount or a hard link under another name matches nothing — a path shape
  is a fact of the name, not of the file.

## 3e. The path of one discrepancy

The firewall can hold two views of one session: the external view of the
monitor (§3, §3a) and the in-process view of the sensor of M2. The
correlation engine compares the two after the session, on the recorded
pair, and every disagreement becomes a `discrepancy` event that the rules
of `policies/correlation.yaml` judge. The measurement behind this section
is `research/bypass/correlate.sh` and the M5 section of
`research/bypass/FINDINGS.md`.

1. **The engine reads three files.** `agent-firewall correlate <trace>
   --sensor <sensor-trace> --reg <record>` reads the monitor's trace (the
   observed view), the sensor's trace (the expected view) and the
   registration record that names every sensor instance the session
   installed. The record is the key: an empty record means no sensor, and
   then no disagreement can exist.

2. **Four disagreements are sensed.** A sensor instance that proved it
   talks (a heartbeat) and then said nothing through a gap wider than the
   quiet window while the external view shows its process alive inside the
   gap (`sensor_silent_subtree`); a spawn the sensor reported whose exec
   the external view never saw (`spawn_reported_unseen`); a spawn the
   external view saw whose successor image never registered
   (`spawn_seen_unreported`); and a held connection that crossed a
   registered process without crossing libc (`action_contradicted`). The
   reported spawn measured zero on both corpora, because the exec stop of
   §3 is a kernel guarantee for the whole tree — no rule ships for it. The
   contradicted action covers connections only: the write-open comparison
   fired 30 times on one 28-second corpus session — `mkstemp` and other
   glibc-internal opens, retried lock attempts, reflog re-opens never
   cross the interposed libc — and the gate refused it. The measurement
   stays runnable behind `correlate --compare-write-opens`.

3. **The keying is the decision log's.** A static binary (`dynamic_link:
   false`, a fact the monitor reads from the program file at the exec stop)
   can never load a preload, a child that stripped the preload from its
   environment raises the tamper fact of §3d instead, a child that
   registered after its exec — `posix_spawn` does, without an intent — is
   quiet, a call the kernel floor refused or the policy rejected never ran
   and the sensor is honest about it, and the loader's own opens between
   an exec stop and the successor's registration are plumbing, not the
   program acting. A thread reports under its group leader, because the
   sensor reads `getpid` and the monitor reads the acting thread.

4. **Two rules quarantine, one reports.** The silence and the unreported
   spawn carry `quarantine: true`: they name acts that only an attack on
   the sensor's visibility produces — nobody blinds a sensor inside a
   living process, nobody deletes the sensor's library from under its own
   session — and the benign corpus exercised their negatives (every
   instance of every corpus run beat at about 1 Hz; every dynamic child of
   the corpus registered after its exec). The contradicted connection
   reports instead, because the corpus is offline and cannot prove that
   negative; the quarantine waits for sessions with real network traffic.
   The engine itself never suspends anything: it reads finished traces,
   reports the findings, and writes them as one schema-valid trace that
   `replay` judges with the current rules. Live judging — the monitor
   correlating while the session runs — is the alpha work of M6.

5. **The gate is the negative half.** The benign corpus of M1, with the
   sensor active, fired zero of the three rules in all three filter modes;
   the seeded techniques of the harness fired each of them. A healthy
   instance talks at about 1 Hz — the heartbeat thread of the registration
   record fills every idle second — which is what makes a 3-second quiet
   gap a signal instead of a pace.

### What the correlation layer does not cover

* **The judge runs after the session.** A discrepancy cannot stop the
  action that produced it; it names the act for the ruling that follows.
  The sensor stays what it always was — a reporter, never a boundary.
* **A read open is never compared.** The loader machinery of a normal
  session — the program's libraries, a `dlopen` and its dependencies —
  never crosses the interposed libc, and a rule that compared reads would
  fire on every dynamic exec. The write half and the connections see the
  same attacker.
* **A frozen process does not stay frozen under the product.** The
  monitor's wait loop continues a tracee that stopped itself, so a
  whole-process `SIGSTOP` cannot hold a session open (measured: the frozen
  child exits at the freeze instant). The silence fact stays reachable
  through the blinded shape — the sensor's descriptors closed mid-run —
  which raises the silence and the contradiction together.
* **A dynamic program that opens through its own runtime — a Go build with
  cgo, a setuid binary whose loader ignores the preload by kernel order —
  reports nothing and is not a static child.** The corpus of M1 carries no
  such program; the caveat is recorded here so the first report of one is
  read as the known limit and not as a surprise.

## 3f. The path of one telemetry sample

The recorder of §5 already writes the normalized schema; telemetry is a
redacting packaging step in front of it, not a second event format. The
specification is [TELEMETRY.md](TELEMETRY.md); this section states what
ships. The crate is `af-telemetry`, the command family is
`agent-firewall telemetry`, and the crate links no network library —
`cargo tree -p af-telemetry` names `af-core`, `serde`, `serde_json` and
nothing else.

1. **Consent comes first, and nothing else reads it.** The consent state
   is one local file
   (`$XDG_CONFIG_HOME/agent-firewall/telemetry.json`), off by default,
   granular over five scopes (`tree`, `actions`, `content`, `env`,
   `identity`), revocable at any time. No other command reads it: `run`
   reads it only for a session that passed `--telemetry`, and a session
   without the flag never touches the file. With telemetry off the
   product is complete.

2. **A trigger centers the sample.** A quarantine, a tamper fact, a
   signal to the monitor, a discrepancy, a question to the user, or a
   policy decision above `allow` starts one sample; 20 events before and
   20 after form the window, and windows that touch merge. A quiet
   session makes no sample.

3. **Every field is chosen by scope, then redacted, then pseudonymized.**
   The environment-value redaction of the monitor (RESEARCH.md §4) is
   generalized to every free text: an assignment whose name holds a
   secret marker keeps the name and loses the value, a credential with a
   known prefix is swallowed whole, and the matcher errs toward
   redaction. Environment values never travel in any scope; observed
   content travels only under `content`, secret-redacted and cut to 2000
   characters; the session baseline never travels; time travels as
   milliseconds after the session start; the session identifier becomes a
   truncated SHA-256 reference; process identifiers become `p1`, `p2`, …;
   the home directory, any login under `/home`, and the host name become
   `<home>`, `<user>` and `<host>`.

4. **A sample is a local file that the user rules.** It is written to the
   outbox (`$XDG_DATA_HOME/agent-firewall/outbox`, by default under
   `~/.local/share`) as pretty JSON, one file per sample, inspectable with
   a text editor or `telemetry inspect`, and destroyed with
   `telemetry destroy`. The research backend of DIRECTION.md §8 does not
   exist — not a client, not a stub — and the sample's life is generated →
   inspected → destroyed on the machine that made it.

### What the telemetry layer does not do

* It never decides anything and never interrupts anything: the packaging
  runs after the session ended, and no rule, no verdict and no boundary
  reads a sample.
* It sends nothing and prepares nothing to be sent. The pipeline's front
  end stays the manual workflow of `research/threats/`.
* It is not a reporting channel for the user: the session's own
  explanations (§3a's `kernel_denied`, the approval chain) are the
  product surface; the sample is research packaging.

## 4. The enforcement boundary

**The firewall has two decision boundaries — the entry of the `execve`
system call and the `seccomp` stop of a held system call — and one kernel
floor under them that makes the "always no" rule classes impossible before
the program starts (section 3c).**

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

The kernel floor is strong in its own way:

* it decides in the LSM hook, with no supervisor in the loop, at a measured
  cost of 0.98×–1.07× on the benchmark of the spike — zero within the
noise;
* it was fixed before the program started, so nothing the program does can
  race it, and 0 of 6 escape attempts worked in the spike, a new user
  namespace included;
* it covers actions the boundaries never see — a delete inside a running
  program, a read of a key in a program that never starts a second process.

### What the boundaries cannot stop

* **Content that leaves through a connection that is already open.** The
  firewall sees the `connect`. The statement goes out later through `write`
  or `sendto` on the open socket. Holding those calls was measured at 8.8× on
  a chatty program, which is the same order as the full system-call tracing
  that this design rejected. Seeing that content needs a proxy for the
  protocol, not a system-call filter.
* **A delete and a rename inside a granted tree.** The kernel filter holds
  neither. The floor makes a delete outside the granted trees impossible,
  and a delete inside the work tree is judged at the command that does it.
  The normalized schema has the event kinds (`file_delete`, `file_rename`);
  only the in-process research sensor produces them today
  (`research/spikes/inprocess/`), and no shipped rule can act on them.
* **Batch input and output through `io_uring`.** The operations run inside
  the kernel through one `io_uring_enter` call and make no per-operation
  system call, so both boundaries and the in-process sensor record
  nothing. Measured live with a write-intent ring open: zero events in
  every filter mode, and no rule could ever act on them
  (`research/bypass/FINDINGS.md`, gap 1; scenario `evade-15`). The known
  mitigations are kernel-side — a gate on the setup and enter calls, or
  ring-operation auditing — and whether such a gate may ask a question is
  an interruption-budget decision, because some runtimes use io_uring for
  ordinary file work. On a machine where the gap matters, check
  `/proc/sys/kernel/io_uring_disabled`.
* **A write to a credential store under the work tree or under `/tmp`.** The
  floor hides the stores of the home directory; a `.ssh` created inside the
  work tree is normal writable space, and the rule keeps its question there.
* **An `execve` from an anonymous file descriptor.** Measured: a program
  exec'd from a `memfd` runs under the floor. `process.exec.fileless` keeps
  its question.
* **`chmod` and ioctls.** Landlock mediates neither, and the floor handles
  no network right at all.
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
| `seccomp` `RET_TRACE` filter | **ships** (§3a) | file opens and connections inside a running program; a signal to the monitor itself, held before it runs (§3d) |
| in-process instrumentation (`LD_PRELOAD`) | **measured sensor** — spike of 2026-08-31 (`research/spikes/inprocess/`), not product-integrated | semantics close to the agent: about-to-exec, small-file content, delete/rename, dlopen, environment; durable instance registration for M4/M5; never a boundary |
| correlation of expected vs observed | **measured engine** — `agent-firewall correlate` (§3e), post-hoc over the recorded pair, three rules shipped on a zero-benign gate; live judging is M6 | a discrepancy between the in-process view and this document's sensors is a high-severity signal on its own (DIRECTION.md §3.4) |
| Landlock | **ships** (§3c) | in-kernel "always no" rules; removes the question ([DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §4) |
| `fanotify` / eBPF | enterprise tier | privileged observation, later (DIRECTION.md §10) |
| Windows hooks (Win32/`ntdll`) | surveyed, not built | the sensor candidate is chosen — `ntdll` trampolines in a launch-injected DLL (`research/spikes/windows-notes/`) — with the launch loop (debug events + job object) as the no-admin observer and ETW/WFP/minifilter as the privileged tiers; the unprivileged floor candidates are AppContainer and the experimental sandbox launch API. No Windows code exists

Five additions land in this architecture without changing sections 1–7:

* **The kernel floor — shipped (§3c).** Landlock turns the "always no" rule
  classes of the built-in pack into kernel enforcement before the first
  program runs, at a measured cost of 0.98×–1.07× — zero within the noise —
with an explainer that names the
  rule class behind every `EACCES` it causes.
* **Agent detection and identity — shipped (§3b).** A detector subsystem
  tags the session root at launch, the tag propagates through the provenance
  graph that already exists, every event carries it, and a descendant that
  detaches is flagged `unlinked` — the B.6 liveness fact — and never as
  foreign (DIRECTION.md §4, §5).
* **Tamper detection and quarantine — shipped (§3d).** A signal to the
  monitor is held by the kernel filter before it runs; a detached
  descendant, a killed program that came back, a child with no sensor
  preload and a process that outlived the session are sensed facts of the
  schema; the rules of the tamper pack judge them; a rule that asks for it
  suspends the whole tree, shows the evidence and takes one ruling; and the
  recorder writes the evidence through, so a killed monitor leaves the
  record instead of erasing it. The interruption budget governs every rule
  of the pack: two facts report instead of asking, because normal tooling
  makes their shape.
* **Event provenance for research — shipped (§3f).** The recorder of §5
  already writes the normalized schema; the telemetry pipeline
  ([TELEMETRY.md](TELEMETRY.md), DIRECTION.md §7) is a redacting packaging
  step in front of it, not a second event format: consent-gated by scope,
  redacted and pseudonymized by design, written to a local outbox, sent
  nowhere — the backend is future work.

The soundness rule of §3a binds every new sensor: **decide on an object,
never on a pointer into the memory of the program you are judging.** An
in-process sensor is exempt as a *reporter* — its reports are advisory input
to correlation — and never as a *decider*.
