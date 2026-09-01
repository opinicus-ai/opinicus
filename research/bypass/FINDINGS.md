# The bypass matrix: what the two shipping sensors hold, see, and miss

Harness: `research/bypass/`. Ticket: `[af-1]` (W2 of `docs/DIRECTION.md` §11).
Machine: Fedora 43, kernel 7.0.9, `x86_64`, uid 1000, no root, no `sudo`,
`yama/ptrace_scope = 0`, `kernel.io_uring_disabled = 0`, gcc 15.3.1,
go 1.25.12. Every number below comes from `results/` (regenerable). Re-run
with `./run.sh` (77 technique runs plus the benign corpus, about 2 minutes).

## Verdict

The two shipping sensors cover far more than their reputation suggests, and
they fail in exactly three places, each for a named structural reason. Of the
twelve technique actions run against the product posture (builtin rules,
`--approve deny`), the firewall **held** one of the most dangerous ones — a
database client reading `DROP DATABASE` from a file — in all three filter
modes, it **saw** seven, and it was **silent** on four. Every silent cell has
a mechanism that would close it, and none of the mechanisms is "a better
rule": two need new kernel filter coverage, one needs an event kind, one
needs the input capture to stop keying on program names. The harness also
caught the product in one behaviour the documents did not know: **a killed
monitor erases the evidence of its own killing** — the trace survives with
exactly one line.

## The matrix

`held` — the action did not happen. `seen` — the action happened and the
trace carries an event for it. `silent` — the action happened and no event
covers it. The probe pass (catch-all rules, no builtin pack) answers a
different question: *could a rule act on this event at all?* `holdable` —
the event was delivered to the engine. `no event` — nothing was delivered.
`held-indirect` — the probe held a different action of the same run.

| technique / action | scenario | baseline | builtin w-o | builtin a-o | builtin off | probe w-o | probe a-o | probe off |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| static-file-net / write | adjacent: evade-04, evade-06 | works | seen | seen | silent | holdable | holdable | no event |
| static-file-net / connect | adjacent: evade-04, evade-06 | works | seen | seen | silent | holdable | holdable | no event |
| rawsys / file | adjacent: evade-06 | works | seen | seen | silent | holdable | holdable | no event |
| rawsys / connect | adjacent: evade-06 | works | seen | seen | silent | holdable | holdable | no event |
| escape-setsid / leaf | evade-08 | works | seen | seen | seen | holdable | holdable | holdable |
| outlive / daemon | behavior-03 | works | seen | seen | seen | holdable | holdable | holdable |
| uring / uring | evade-15 | works | **silent** | **silent** | **silent** | no event | no event | no event |
| delete-rename | fs-12, fs-05, fs-07 | works | **silent** | **silent** | **silent** | held-indirect | held-indirect | no event |
| cred-read / read | secrets-01 | works | silent | seen | silent | held-indirect | holdable | no event |
| fileclient / byfile-unknown | adjacent: evade-03 | works | **silent** | **silent** | **silent** | held-indirect | held-indirect | no event |
| fileclient / byfile-psql | adjacent: evade-03 | works | **held** | **held** | **held** | held-indirect | held-indirect | held-indirect |
| payload-assembly / assembled | evade-05 | works | seen | seen | seen | held-indirect | held-indirect | holdable |
| pydrop / script-content | **new finding** | works | **silent** | **silent** | **silent** | held-indirect | held-indirect | no event |
| kill-monitor / kill | evade-07 | works | silent, fail-closed | silent, fail-closed | silent, fail-closed | held-indirect | held-indirect | no event |

Rules that fired in the builtin posture, in total: `filesystem.credentials.read`
and `memory.credentials.read-mark` (cred-read at `all-opens` only) and
`database.destructive.drop-database` (byfile-psql, via the input branch, in
all three modes). Nothing else in the pack matches any technique, which is
the interruption budget doing its job: most rows are report-shaped events
waiting for chain-aware rules, not stopping rules.

## What holds — measured

* **The kernel filter is immune to libc bypass.** Static Go binaries and raw
  `syscall()` file and network access produced the same held opens and
  connects as libc programs: the filter selects on the syscall number, and a
  raw `openat` carries the same number. The classic `LD_PRELOAD` evasions
  (`env -u`, static linking, direct syscalls — `research/spikes/baselines/`)
  all fail against the external stack.
* **The launch-model tree cannot be escaped by the classics.** `setsid`,
  double fork and a re-executed leaf stayed fully traced and fully
  attributed in every mode (evade-08). The escape surface is what the
  documents already name: processes the session never started.
* **A detached daemon cannot outlive the session's knowledge.** The session
  waited 3.0 s for the daemon and recorded it (`session_end` with
  `process_count: 2`). It does not escape — but nothing *senses* the
  detachment: no rule can ask "did this child outlive its parent?", and a
  30 s daemon would hold the session open for 30 s. That is requirement B.6,
  unbuilt (behavior-03).
* **The input capture holds a client reading its payload from a file.** The
  same binary named `psql` with `-f drop.sql` was held at the exec stop in
  all three modes, by `database.destructive.drop-database`'s input branch —
  the statement never appeared in argv. The same binary named `fileclient`
  was silent everywhere. The name lists decide everything.
* **Fail-closed holds under attack.** The SIGKILL to the monitor took the
  whole tree with it, every time, in every mode (`PTRACE_O_EXITKILL`). The
  attempt never succeeded in surviving.

## The gaps — each with its mechanism

1. **io_uring bypassed the per-syscall filter completely — closed as a
   held boundary on 2026-09-01** (evade-15, measured live,
   `kernel.io_uring_disabled = 0`). One `io_uring_enter` performed
   `IORING_OP_OPENAT` with write intent; no `openat` syscall ever
   happened; the write through the returned descriptor left **zero
   events** in every mode, and no rule could ever act on it. Since the
   `[af-12]` hold, the filter holds `io_uring_setup` and
   `io_uring_enter` in every mode that installs it, the `io_uring` action
   reaches the engine, and the rule `tamper.bypass.io-uring` reports
   every call — the matrix row below measures `seen` in `write-only` and
   `all-opens` (the held call reaches the engine; the road itself stays
   open), `silent` only with the filter off. The road stays open under the shipped pack, because the measured compatibility set
   (`research/bypass/uring-compat.sh`, the decision of
   `docs/DECISIONS.md`, 2026-09-01) found a normal node session makes
   the calls on its own — 36 in one `npm ci` (27 in an earlier identical
   run), 48 in one corpus run — and
   completes when they are refused: a default deny fires on everyday
   work, so refusing the road is a host requirement (the sysctl, or a
   local rule file that replaces the report with a deny).
2. **Delete and rename do not exist** (fs-12, fs-05, fs-07). `unlink` and
   `rename` produced no events; only the *create* was visible. Mechanism:
   hold `unlink`, `unlinkat`, `rename`, `renameat2` in the filter and add the
   event kinds — the schema work the documents already name.
3. **The input capture keys on program names, and distro reality defeats it.**
   Two measured rows:
   * `/usr/bin/python3` is a symlink to `python3.14`; `/proc/<pid>/exe`
     resolves through the symlink, so the program name is `python3.14`,
     which is in no interpreter list. A Python script whose text contains
     `DROP DATABASE` was silent in every mode; the identical script under a
     binary actually named `python` was held (verified separately with a
     copy, since a symlink still resolves). The same shape applies to any
     versioned interpreter. Mechanism: match the interpreter list on the
     resolved executable's *content family* or a maintained name pattern,
     never on an exact basename.
   * A client-shaped binary with `-f payload` that is in no name list is
     silent everywhere. Mechanism: either extend the name lists or capture
     read-opens of small files under a size bound at exec time.
4. **Tamper sensing does not exist, and a killed monitor erases the
   evidence.** The `/proc` scan and the `SIGKILL` left no event in any mode;
   the fail-closed machinery killed the tree as designed; and because the
   recorder buffers its output, the trace survived with exactly **one line**
   (`session_start`) — the attack erased its own record. Mechanism, in
   order: durable (unbuffered) writes for the evidence of a dying monitor;
   monitor identity as a rule-visible fact (B.5); liveness and teardown
   events (B.6); a tamper event for the scan-and-kill pattern. All four are
   M4/M5 work; this row is their justification.
5. **Read-opens are blind in the default mode** (known, re-measured). The
   credential read was silent at `write-only`, seen at `all-opens` with both
   credential rules firing. The default stays right (a read is 99.7 % of
   the open traffic on the synthetic W2 workload,
   `research/spikes/seccomp-ptrace/FINDINGS.md`); the row exists to keep
   the trade-off visible.

## What feeds the next milestones

* **M2 (in-process sensor):** the pydrop and byfile rows are its job
  description. A sensor close to the process sees the interpreter's real
  identity and the file its arguments name, regardless of name lists. Its
  registration record must also be durable, or a killed monitor loses it
  with the rest.
* **M4 (tamper and quarantine):** the kill-monitor row is the requirements
  document: sense the scan (B.5 facts), survive with evidence (durable
  writes), quarantine on the attempt (B.6 liveness for the dying tree).
* **M5 (correlation):** payload-assembly is visible end to end and still
  needs a chain rule to become a signal — write, chmod, exec is exactly the
  two-event shape the session memory was built for. A `marked` rule
  (write-intent open of a script → exec of that script) is expressible in
  the shipped engine today and needs no new sensor.
* **The ledger:** io_uring is confirmed live and unmitigated on a stock
  Fedora desktop (evade-15); pydrop is a new catalogue candidate for the
  next research run.

## The benign corpus

A scripted normal session — git init/add/commit/log/status, `cargo new` +
`cargo build` + run, `npm init` + `npm --version`, `python3`, `find`,
`grep` — under `--approve deny`, in all three filter modes:

| mode | questions | notes (info-level, allow) | fw exit | session exit |
| --- | ---: | ---: | --- | --- |
| write-only | 0 | 1 | 0 | 0 |
| all-opens | 0 | 5 | 0 | 0 |
| off | 0 | 1 | 0 | 0 |

The notes are by design, not questions: `allowlist.filesystem.temp-cleanup`
fires once on the corpus's own cleanup (`rm -rf` of the harness's temporary
crate directory, an allowlisted safe form), and `all-opens` adds four
`memory.credentials.read-mark` notes from `npm` reading `~/.npmrc`. The
marks are the credential-chain memory doing its job at info level.
`kubectl` is not installed on this machine and the corpus could not
exercise it. One harness lesson is recorded in `benign.sh`: a corpus crate
created inside the repository tree is registered into the repository's
cargo workspace by `cargo new` itself (it rewrites the root manifest), so
the corpus crate is now created and built outside the repository, and the
repository manifest excludes `tmp/`.

## After M4 — the tamper gate (2026-08-31)

M4 made the attempts of this harness sensed states. The gate script is
`./tamper.sh` (run it after `cargo build --release`); the negative side is
`./benign.sh`, which now counts quarantines and must stay at zero.

| technique | fw exit | fact events | rule matches | quarantines | rulings | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| kill-monitor | 3 | 1 | 1 | 1 | 1 | fires and quarantines |
| escape-setsid | 0 | 3 | 3 | 0 | 0 | fires as a report |
| respawn | 3 | 2 | 2 | 2 | 2 | fires and quarantines |
| strip-preload | 3 | 1 | 1 | 1 | 1 | fires and quarantines |

Three runs of the gate gave the same table every time.

What moved, measured on the same machine as the matrix above:

* **kill-monitor went from `silent, fail-closed` to `held`** in the
  `write-only` and `all-opens` cells of the builtin posture. The kernel
  filter now holds a signal whose target is the monitor — the comparison
  runs in the BPF program on the call number and the identifier, before the
  call happens — so the `SIGKILL` never runs: the tamper rule fires, the
  tree is quarantined, the ruling (the harness answers with `--approve
  deny`) refuses the call, and the technique prints `blocked rc=-1` where M1
  measured a dead monitor and a one-line trace. The `off` cell keeps the
  fail-closed outcome and gains the durable record: with the floor also off,
  so that the kill really succeeds, the trace of the killed monitor now
  holds the `process_exec` of the attacker (2 lines against the 1 line of
  M1) — the recorder writes every process event through.
* **escape-setsid and outlive now carry the B.6 facts.** The detach raises
  `process_unlinked` (M3) plus a `tamper` fact, and the daemon that outlives
  the root raises its own `tamper` fact. Both rules **report** — the first
  version of the detach rule quarantined, and the corpus refused it:
  `git maintenance run --detach`, which runs on every `git init` and
  `git commit` of the corpus, raises the same fact. The interruption budget
  wins over the severity; the finding is recorded here because it is the
  gate doing its job.
* **Two new seeded techniques** joined the harness: `respawn` (a program
  the firewall denied, started again by the same parent — 2 facts for 3
  rounds, because the first round is the kill itself) and `strip-preload`
  (a child whose environment carries no `LD_PRELOAD`, run with the
  in-process sensor of `[af-2]` active — the session facts name the sensor
  and its registered instances, and the fact is sensed at the exec stop).
* **The benign corpus stays quiet.** Zero questions, zero agent tags and
  **zero quarantines** in all three filter modes, with and without the
  sensor; the one `tamper` event per run is the git-maintenance detach
  report, which asks nobody. The M2 corpus gate re-ran green (zero
  questions, zero sensor silence, zero preload facts on ~4 400–7 700 sensor
  events per mode).
* **The cost is not measurable.** Interleaved A/B on the shared benchmark
  (the pre-M4 binary against the M4 binary, 3 rounds of 5 runs each):
  W1 exec 352 vs 358 ms, W2 file 146 vs 145 ms, W3 mixed 252 vs 253 ms —
  1.00×–1.02×, inside the noise of the machine. The signal rules match no
  syscall of a normal session, and the four extra BPF blocks cost a few
  instructions per call.

## After M5 — the correlation gate (2026-08-31)

M5 made the two views of one session comparable. The engine is
`agent-firewall correlate` (`crates/af-correlate`): it reads the monitor's
trace (the observed view), the sensor's trace and registration record (the
expected view), raises every disagreement as a `discrepancy` event, and the
rules of `policies/correlation.yaml` judge it. The gate script is
`./correlate.sh` (run it after `cargo build --release`); the negative side
is the benign corpus under the sensor, in all three filter modes. Three
runs of the gate gave the same table every time.

| rule | bypass firings | benign firings | where | verdict |
| --- | ---: | ---: | --- | --- |
| `correlation.sensor.silent-subtree` | 1 | **0** | sensor-blind: 1 | ships, quarantines |
| `correlation.action.contradicted` | 1 | **0** | rawsys: 1 (the connect) | ships, reports |
| `correlation.spawn.unreported` | 2 | **0** | sensor-unlink: 2 | ships, quarantines |
| `spawn_reported_unseen` (no rule) | 0 | 0 | — | unreachable: no rule |

Bypass rows, one seeded technique per kind: `sensor-blind` closes the
sensor's own descriptors mid-run (fd sweep to 1024 — the M2 spike moved
them near 900 with close-on-exec, so the old 3..63 sweep blinds nothing),
and raises the silent subtree (5999 ms quiet while the external view shows
the process alive); `sensor-unlink` deletes the sensor's library from
under the live session and spawns two dynamic children whose environment
still names the preload — both execs are unreported spawns; `rawsys` holds
its raw-`syscall()` connect while its registered instance reports nothing
(the contradicted connection); `strip-preload` is the control and stays
quiet for correlation, because the child's environment names no sensor to
contradict — M4's live `preload_stripped` fact owns that case.

The benign corpus under the sensor ran with zero questions, zero agent
tags, zero quarantines and **zero correlation firings** in all three
filter modes (458 / 3511 / 260 product events against 4650 / 7680 / 4408
sensor events and 159 / 160 / 159 registration lines).

Three results the gate forced, all recorded in `docs/DECISIONS.md`:

* **The write-open comparison is refused, with numbers.** Comparing every
  held write open against the sensor's reports fired **30 times on one
  corpus session** (write-only; 49 with all-opens): git writes its loose
  objects through `mkstemp`, which glibc opens with internal calls the
  preload cannot see; gcc's temp files and rustc's codegen outputs take
  the same road; git reflogs open twice in the product view against once
  in the sensor's; and bash probes `/dev/tty` with a write open that fails
  under a pipe (the sensor reports successes only). A rule on that
  comparison fires on shapes normal tools make. It stays measurable as
  research telemetry behind `correlate --compare-write-opens`, and the
  product compares connections only — which the corpus exercises through
  libc or not at all, so the contradicted-connection rule reports instead
  of quarantining until sessions with real network traffic prove its
  negative.
* **A frozen tracee is the monitor's own defense.** `sensor-freeze` execs a
  fresh image (so its constructor arms a real heartbeat thread — a plain
  fork inherits a thread that never restarts), proves it talks, and
  SIGSTOPs itself. The monitor's wait loop **continues a tracee that
  stopped itself**, so the child runs through its freeze instantly
  (measured: it exits at the freeze instant; the marker proves the run;
  zero findings). The silence fact stays reachable through the blinded
  shape, which raises the silence and the contradiction together.
* **`spawn_reported_unseen` is unreachable in a launch session.** The exec
  stop is a kernel guarantee for the whole tree (the M1 escape row
  measured that nothing of the tree escapes the tracer), so a reported
  exec that the external view never saw cannot exist here. The check
  stays in the engine and measured zero on both corpora; no rule ships
  for it. A future attach mode does not carry the guarantee.

The cost of the one live-path change — the monitor reads the program file
at the exec stop to learn whether it needs the dynamic linker — is not
measurable: the shared benchmark gives W1 351 / W2 148 / W3 251 ms against
M4's 352 / 145 / 253 (`research/bench/bench.sh`, medians of 7).

What keyed the quiet: a healthy instance is dense — the heartbeat thread
fills every idle second at about 1 Hz, so a 3-second quiet gap in an
instance that proved it carries the thread is a signal, not a pace; every
dynamic child of the corpus registered after its exec (`posix_spawn`
registers without an intent, measured in M2, and the engine asks for the
registration **at or after** the exec stop, because a preloaded fork
registers just before it); static children are excluded by the
`dynamic_link` fact the monitor now reads from the program file at the
exec stop; and a call the kernel floor refused or the policy rejected
never ran, so the sensor is honest when it reports nothing for it.

## After M8 — the evidence gate (2026-09-01)

M8 (`[af-9]`) made the firewall's own evidence trail rule-visible. The
session metadata now carries the trace path the launcher opened
(`meta.trace`) and, with the in-process sensor active, the sensor's trace
and registration paths (`meta.sensor.trace`, `meta.sensor.registration`) —
B.5 facts in the shape of paths, matched by the new `evidence_target`
field of the rule format. The rules are in `policies/tamper.yaml`; the
gate script is `./evidence.sh` (run it after `cargo build --release`),
and two runs gave the same table every time. The negative side is
`./benign.sh` plus the in-file negative tests — 28 of the pack's 700
policy tests belong to the five evidence rules, 16 of them negative.

| case | what ran | outcome | evidence (same run) |
| --- | --- | --- | --- |
| a1 trace truncation | `open(O_TRUNC)` of the `--trace` file | **prevented** | rule hits 1, quarantines 1, fw exit 3, file intact, no forged line |
| a2 trace forgery (append) | `open(O_APPEND)` of the `--trace` file | **prevented** | rule hits 1, quarantines 1, fw exit 3, file intact |
| a3 sensor trace truncation | `open(O_TRUNC)` of `AF_SENSOR_TRACE` | sensed (report) | rule hits 3, quarantines 0; the sensor's own writes are 2 of the 3 |
| a4 sensor registration truncation | `open(O_TRUNC)` of `AF_SENSOR_REG` | sensed (report) | rule hits 3, quarantines 0, record truncated, report in the firewall's trace |
| b1 rohrpost log rm | `rm -f .rohrpost/log.jsonl` | **prevented** | rule hits 1, quarantines 1, fw exit 3, log intact |
| b2 rohrpost log truncate | `sh -c ': > .rohrpost/log.jsonl'` | sensed (report) | rule hits 1, quarantines 0, log emptied, report survives in the firewall's trace |
| b3 rohrpost log unlink (python) | `python3 -c "import os; os.remove(...)"` | **gap** | rule hits 0, quarantines 0, log gone |
| c1 transcript rewrite | `open(O_TRUNC)` of a recorded `~/.claude/projects/**.jsonl` | sensed (report) | rule hits 1, quarantines 0, turn dropped, report survives |
| c2 transcript sed -i | `sed -i /curl/d` of the transcript | sensed (report) | rule hits 1 (the temp-file open inside the store), quarantines 0, turn dropped |
| c3 shell history truncate | `sh -c ': > $HOME/.bash_history'` | sensed (report) | rule hits 1, quarantines 0, history emptied |
| d1 trace unlink | `unlink` of the `--trace` file | **gap** | rule hits 0, quarantines 0; the trace file is gone after the session — the recorder writes on its open descriptor, so the record died with the inode when the monitor closed it |

The rules: `tamper.evidence.trace-write` (approval_required + quarantine,
keyed on the B.5 fact — the launcher is the only writer of the session
trace, so the question costs a normal session nothing),
`tamper.evidence.sensor-record-write`, `tamper.evidence.rohrpost-write` and
`tamper.evidence.transcript-write` (report-level; the reasons are below),
and `tamper.evidence.rohrpost-erase` (approval_required + quarantine, on
the erase verbs). The pack grew from 155 to 160 rules (`policy check`).

Three budget calls the gate forced, each with its measurement:

* **The sensor's own records cannot be a question.** The sensor of M2
  appends to `AF_SENSOR_TRACE` and `AF_SENSOR_REG` with raw
  `syscall(SYS_openat, ...)` opens from inside every instrumented child —
  the a3 run shows 2 of its 3 rule hits are the instrument's own writes
  (the trace append and the registration append of one payload process),
  and the sensor-active benign corpus of `correlate.sh` produces **72
  report firings and zero questions** in one normal session (write-only;
  72 in all-opens, 0 with the filter off — every hit is
  `tamper.evidence.sensor-record-write`). The instrument's write and the
  eraser's rewrite are the same open to the filter, so the rule reports
  where the trace rule quarantines. Quarantining there would have put a
  question on every event of every sensor-active session — the exact
  regression the benign corpus exists to catch.
* **Rohrpost appends and transcript appends are name-keyed reports.** The
  repository's own workflow writes `.rohrpost/log.jsonl` from inside
  monitored sessions (`rp` appends, the fold rewrites the snapshot), and
  an agent harness appends to its active transcript on every turn; an
  open cannot tell an append from a rewrite, so both stay reports. The
  erase rule asks only on verbs with no legitimate shape (`rm`, `mv`,
  `shred`, `truncate`, `unlink` naming the two files).
* **The two gaps are structural, pre-loss, and named.** The kernel filter
  holds no `unlink` and no `rename` (documented in
  `crates/af-monitor/src/seccomp.rs`), so an in-process unlink with no
  erase verb on any exec (b3) and an unlink of the trace file itself (d1)
  reach no rule. d1 is the total-loss case: the recorder keeps writing to
  the unlinked inode and the record dies when the monitor closes it. A
  same-UID process of the tree can also reach the trace through a symlink
  or a hard link under another name — the B.5 fact compares the path
  string, and a different shape answers nothing. Closing these needs
  `unlink`/`rename` in the filter and the event schema, the same schema
  work gap 2 of this file already names.

## After M11-A — the inherited-descriptor gate (2026-09-01)

The inherited-descriptor half of `[af-12]` (review P0-7, experiment
EXP-T3). The gate script is `./inherit.sh` (run it after
`cargo build --release`); the fixtures are `techniques/inherit-fd.c` and
`techniques/inherit-scm.c`; the raw table lives in `results/inherit.md`.
Every row below is from one run of that script on the matrix machine
(kernel 7.0.9, x86_64).

| row | write-only | all-opens | off |
| --- | --- | --- | --- |
| launch-inherited (pre-hygiene binary) | leaked: fds=6, writes landed | leaked: fds=6, writes landed | leaked: fds=6, writes landed |
| launch-inherited (shipped binary) | **closed: fds=3, every write EBADF** | **closed: fds=3, every write EBADF** | **closed: fds=3, every write EBADF** |
| in-tree fork-inheritance | open gap: child use silent | open gap: child use silent | open gap: nothing at all |
| SCM_RIGHTS mid-run pass | open gap: child use silent | open gap: child use silent | open gap: child use silent |

What the rows say, measured:

* **The launcher vector was open, not closed.** A hostile launcher that
  pre-opened a writable file, a connected socket and a `memfd` (no
  close-on-exec) plus a `pidfd` and exec'd the firewall itself delivered
  three of the four capabilities into the session root of the pre-hygiene
  binary: the payload counted **6 descriptors** — stdio plus the file,
  the socket and the `memfd` — and the file write and the socket send both
  landed, in all three filter modes; no `open` and no `connect` of the
  session ever crossed an observation point. The `pidfd` is the control
  row: `pidfd_open` sets `FD_CLOEXEC` itself (measured with
  `fcntl(F_GETFD)`), so the kernel closed it at the exec with no help —
  which is exactly the treatment the hygiene now gives the rest. This
  also corrects the review's premise: Rust's `std::process::Command` does
  not close inherited descriptors — measured on this machine, parent pipe
  descriptors survive into the exec'd child on both the `posix_spawn` and
  the `pre_exec` path (`docs/THREAT-MODEL.md` §5.3).
* **The launch hygiene closes it.** The monitor now marks every
  descriptor beyond stdio close-on-exec in the root's `pre_exec`, as the
  last step before `execve`
  (`close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`;
  `crates/af-monitor/src/tracer.rs`). The same hostile launcher against
  the shipped binary: the payload counts **exactly 3** (0, 1, 2) and the
  file, socket, `memfd` and `pidfd` writes all answer **EBADF**, in every
  mode. The floor report pipe still works (the session reports its 6
  enforced rule classes), and the two new `af-monitor` tests pin the
  behaviour: the launch closes an inherited non-CLOEXEC descriptor, and
  the floor report survives the hygiene. Both tests passed in the run of
  2026-09-01 04:29 (63 of 63 of the crate); the same suite cannot re-run
  on this machine until reboot, because the hostile matrix below left
  yama at scope 3 — a one-way switch — and at scope 3 every session test
  refuses the launch (`PTRACE_TRACEME` answers `EPERM`), the same
  `no-session` row that matrix measures for itself.
* **In-tree fork-inheritance stays open.** A traced process that opens
  and connects itself produces both events (`file_open` write=1,
  `network_connect` 1 in the two filtered modes) — the opens are seen —
  but the forked child's `write` and `send` through the inherited
  descriptors leave **no event at all**, and the writes land. `write` is
  not in the held set (it was measured at 8.8× and rejected), so no rule
  can act on the use. Honest note: this row's parent opens are *seen*, so
  a chain-aware rule on the open plus the fork could raise a signal —
  none ships today.
* **SCM_RIGHTS stays open.** The parent's `connect` is an event in the
  two filtered modes; the descriptor handed over `sendmsg`/`SCM_RIGHTS`
  is installed in the child without `FD_CLOEXEC`, and the child's `send`
  through it leaves no event in any mode. The kernel installs received
  descriptors without the flag, so the capability would even survive a
  later `exec` of the child — the launch hygiene arms only at the root's
  first `execve`. Named out-of-scope until a boundary tier exists
  (`docs/DECISIONS.md`, 2026-09-01).
* **The monitor's own descriptors are already clean.** The audit of the
  product crates found exactly one raw descriptor creation — the floor
  report pipe, opened with `O_CLOEXEC|O_NONBLOCK`
  (`crates/af-monitor/src/tracer.rs`, `report_pipe`); every other file is
  a Rust `std` open, which is close-on-exec by default, and the product
  creates no sockets at all. The launch hygiene makes the point moot for
  the session: even a non-CLOEXEC descriptor of the monitor cannot
  survive the root's `execve`.
* **The benign corpus: quiet where the hygiene can speak.** The corpus
  ran in `off` mode with the hygiene active — zero questions, zero agent
  tags, zero quarantines, `fw_exit=0`, corpus to the end
  (`results/benign-summary.txt`) — so no normal tool of the corpus needs
  a descriptor beyond stdio at launch; the hygiene is mode-independent,
  so this speaks for every mode. The two filtered modes of this run
  failed on the other half of `[af-12]` in the same tree: the new
  `tamper.bypass.io-uring` deny refuses the six `io_uring_setup` calls
  of the corpus's `npm init -y` (`fw_exit=3`, questions=6,
  `results/benign-write-only/trace.jsonl`). That rule and the filter
  that feeds it belong to the io_uring work in flight, not to the launch
  hygiene; reconciling it is this gate's neighbour, not this row.

What would close the two open rows: a boundary tier. Holding `write` on
inherited descriptors is the measured 8.8× price again, a per-fd
provenance (`dup`/`dup2`/`F_DUPFD`/`SCM_RIGHTS` in the filter plus a
descriptor table in the monitor) is the honest middle, and both are M11
contract decisions, not rule work. Until one exists, **no sentence may
claim coverage of a capability the tree did not open during the session**.

## After M11-hostile — the hostile same-UID matrix (2026-09-01)

The gate script is `./hostile.sh` (ticket `[af-12]`, review P1-6 / EXP-T2).
Five techniques attack the monitor **from outside the monitored tree**:
`hostile-ptrace` (PTRACE_ATTACH + PTRACE_POKETEXT of the same word, so a
successful write proves the capability and changes nothing), `hostile-vmem`
(process_vm_readv/writev of the same byte into an anonymous writable
mapping — on this kernel `process_vm_writev` answers EFAULT for a
file-backed private page), `hostile-procmem` (pread/pwrite of the same byte
through `/proc/<monitor>/mem`), `hostile-pidfd` (pidfd_open, pidfd_getfd of
the monitor's standard output, then pidfd_send_signal SIGKILL) and
`hostile-extkill` (`kill -KILL` from a shell outside the tree). Each finds
the monitor the way an attacker would — a `/proc` scan for the payload
whose command line names a harness marker, then that payload's `TracerPid`
— and prints the errno of every step. The session under attack is a plain
payload (`--retention all --approve deny`, kernel floor on). This run of
the matrix needed sudo for the yama sysctl, which the M1 machine did not
have; every other number below comes from the same reference host as the
matrix at the top of this file.

The verdicts: `denied-by-kernel` — the route failed with EPERM/EACCES, and
yama, not the firewall, said no (the firewall holds none of these routes;
no event of any kind reaches it). `succeeded-unsensed` — the route worked,
the monitor lived, and nothing recorded it. `succeeded-fail-closed` — the
monitor died and `PTRACE_O_EXITKILL` took the whole tree with it.
`no-session` — yama refused the launch itself, so there was no monitor to
attack. The raw cells of the first run live in
`results/hostile.run1/` (the levels it measured), the re-run's in
`results/hostile/` — `results/` is regenerable and not committed; this
table is the record.

| technique | yama | attack errno | monitor | fw exit | trace lines | session_end | tamper | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hostile-ptrace | 0 | attach=ok poke=ok | lived | 0 | 34 | yes | 0 | succeeded-unsensed |
| hostile-ptrace | 1 | attach=EPERM | lived | 0 | 34 | yes | 0 | denied-by-kernel |
| hostile-ptrace | 2 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-ptrace | 3 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-vmem | 0 | readv=ok writev=ok | lived | 0 | 34 | yes | 0 | succeeded-unsensed |
| hostile-vmem | 1 | readv=EPERM writev=EPERM | lived | 0 | 34 | yes | 0 | denied-by-kernel |
| hostile-vmem | 2 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-vmem | 3 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-procmem | 0 | open=ok pread=ok pwrite=ok | lived | 0 | 34 | yes | 0 | succeeded-unsensed |
| hostile-procmem | 1 | open=EACCES | lived | 0 | 34 | yes | 0 | denied-by-kernel |
| hostile-procmem | 2 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-procmem | 3 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-pidfd | 0 | open=ok getfd=ok send=ok | died | 137 | 10 | no | 0 | succeeded-fail-closed |
| hostile-pidfd | 1 | open=ok getfd=EPERM send=ok | died | 137 | 10 | no | 0 | succeeded-fail-closed |
| hostile-pidfd | 2 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-pidfd | 3 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-extkill | 0 | kill=ok | died | 137 | 10 | no | 0 | succeeded-fail-closed |
| hostile-extkill | 1 | not measured (a) | — | — | — | — | — | not measured (a) |
| hostile-extkill | 2 | — | no session | 2 | 1 | no | 0 | no-session |
| hostile-extkill | 3 | — | no session | 2 | 1 | no | 0 | no-session |

(a) The run-1 cells of `hostile-extkill` at yama 0 and 1 are void: the
first version of the harness called the technique without its `.sh`
suffix and nothing ran (`attack_rc=127` in the raw cells). The yama-0 row
cited here is the same technique measured standalone at scope 0 minutes
earlier: `kill -KILL` of the discovered monitor returned 0, the firewall
process died with 137, the tree died with it, and the trace held the same
10 durable lines with no `session_end` and no tamper event. The yama-1 row
could not be re-measured on this machine (see the one-way note below); the
signal permission check that answers it carries no yama dependency, and
the same check was measured at yama 1 through `pidfd_send_signal`
(`send=ok`, monitor died, fail-closed).

What the matrix says:

* **At yama 0 the monitor is fully rewritable by a same-uid peer.** The
  attach, the `PTRACE_POKETEXT`-shaped write, the `process_vm_writev` and
  the `/proc/<pid>/mem` pwrite all returned success, the monitor never
  noticed, the session ran to its normal end (34-line trace, `session_end`
  present), and no tamper event exists — the firewall senses none of these
  routes today. The techniques wrote identical bytes back, so the
  measurement proves the capability without corrupting its target; a real
  attacker has no such restraint.
* **At yama 1 the kernel denies every ptrace-class route** (EPERM on
  attach, on both `process_vm_*v`, EACCES on the `/proc/<pid>/mem` open,
  EPERM on `pidfd_getfd`). That denial is yama's, not the firewall's — no
event of the firewall fires in those cells, and a machine at scope 0
  (the posture `doctor` presents as supported) has none of it.
* **At yama 2 and 3 there is no session to attack.** The launch itself
  refused: the child's pre-exec `PTRACE_TRACEME` answered EPERM, the
  monitor reported `cannot start …: Operation not permitted`, and the
  whole cell is a one-line `session_start` with the launch failure in its
capabilities. At scope 3 the refusal was also isolated outside the
  product with a two-line C program (fork + `PTRACE_TRACEME` → EPERM).
  `doctor`'s text for scope 2 — “a launched descendant may still trace
  itself” — is contradicted by this measurement and must not be trusted
  over the raw cells.
* **The signal routes succeed at every scope that permits a session.**
  `pidfd_open` always works (it checks nothing), `pidfd_getfd` follows the
  ptrace check, and `pidfd_send_signal`/an external `kill -KILL` follow
  the signal check, which a same-uid process always passes — yama gates
  no signal. Both kills took the tree down through `PTRACE_O_EXITKILL`
  every time: the payload died with the monitor, and the session was
  fail-closed. No tamper event names either kill.
* **The evidence of an assassinated monitor is its missing end.** The
  trace of a killed monitor holds the 10 durable lines that had reached
  the kernel (`session_start`, `process_exec`, `kernel_floor`, two
  `file_open`s flushed behind the next durable process event, forks,
  execs, one exit), no `session_end`, and nothing else. The recorder's
  durable-write rule of M4 is what leaves those 10; the launcher and the
  monitor are one process, so no code of the firewall runs after the kill
  and no pre-loss event can name the assassin. `agent-firewall replay`
  now names the shape after the fact: a `session_start` with no
  `session_end` prints a note that the session never closed its record,
  with the monitor pid of the B.5 fact — post-loss teardown observation,
  not a boundary (four unit tests in `crates/af-cli/src/inspect_cmds.rs`).
* **yama scope 3 is a one-way switch — measured on this machine.** After
  the first matrix run set scope 3, `sudo sysctl -w
  kernel.yama.ptrace_scope=0` answers `Invalid argument` even for root;
  the kernel allows no lowering from 3 until reboot. The reference host
  therefore sits at scope 3 now, and returns to its original 0 (the
  distro default, `/usr/lib/sysctl.d/10-default-yama-scope.conf`) at the
  next reboot. The harness learned the lesson: it restores the original
  value after every level it can, measures 3 only behind `SCOPE3=1`, and
  on a machine already at 3 it measures that one level and says so.

The negative side of this gate is structural this time: **no rule was
added or changed** (the policy packs are untouched by this gate), and the
one product change — the `replay` note — reads a finished trace, so it can
ask nobody anything. The benign corpus itself could not be re-run as the
negative side on this machine: at yama scope 3, this matrix's own
`no-session` rows apply to the corpus too — the monitor cannot launch —
and the machine sits at scope 3 until reboot. Re-run `benign.sh` on a
machine at scope 0–2 to pair this gate with the measured quiet.

## Method (M5)

* The gate builds the techniques and the sensor, runs each seeded
  technique under the product posture (`--approve deny`, write-only) with
  the sensor active, correlates the recorded pair, and counts rule
  firings from the correlate JSON; the benign side wraps
  `research/bypass/benign.sh` in the sensor environment for all three
  filter modes and correlates each pair.
* The findings of every run are also written as schema-valid traces
  (`--emit`); `tests/e2e.sh` T19–T22 proves the emitted findings read
  back, stay quiet where they must, and replay with the current rules.

## Method

* `orchestrate.py` runs every cell: fresh scratch directory, local listener
  where needed, `timeout 12 s` (25 s for the daemon row), `--retention all`
  so witnesses are visible, `--approve deny` as the hostile reviewer.
* The **baseline pass** runs every technique with no firewall first; a
  technique that cannot produce its effect standalone is a broken
  measurement, not a finding.
* The **probe pass** separates "the sensor delivered an event a rule could
  act on" from "a rule happens to exist". It holds writes, connects, execs
  from the harness scratch tree and drop-statements in captured input.
* `classify.py` verifies every effect from the filesystem and the listener
  log — never from the technique's own stdout — parses the trace
  structurally, and prints the matrix. `results/matrix.json` holds one
  record per run.
* The io_uring technique needs no liburing; it sets the ring up through raw
  syscalls and reports which sqe layout the kernel accepted
  (`open_flags` slot on this kernel).
