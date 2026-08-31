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

1. **io_uring bypasses the per-syscall filter completely** (evade-15,
   measured live, `kernel.io_uring_disabled = 0`). One `io_uring_enter`
   performed `IORING_OP_OPENAT` with write intent; no `openat` syscall ever
   happened; the write through the returned descriptor left **zero events**
   in every mode, and no rule could ever act on it. Mechanism: the seccomp
   filter cannot see ring operations at all. Closing it needs either
   `io_uring_register`-restricted setups, an `io_uring_enter`-size heuristic,
   or kernel support (a ring-operation audit hook). Until then it is an
   honest hole, gated only by the sysctl.
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
   file traffic); the row exists to keep the trade-off visible.

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
