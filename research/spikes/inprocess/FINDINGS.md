# The in-process sensor: what semantics close to the agent add

Spike: `research/spikes/inprocess/` (`[af-2]`, milestone M2, DIRECTION.md
§3.1 and §3.4). Machine: Fedora 43, kernel 7.0.9, `x86_64`, uid 1000, no
root, `yama/ptrace_scope = 0`, gcc 15.3.1, load average 1.8–3.9 (16 users)
at bench time. Every number below comes from a command in this directory or
in `research/bypass/` (regenerable). Re-run: `./run.sh` (self-check),
`research/bypass/run.sh` (the preload matrix pass and the benign corpus),
`./run-corpus.sh` (the corpus gate), `./bench.sh` (overhead).

## Verdict

**Keep the sensor.** The gate asked one question — do the semantics that
only an in-process view can have justify a sensor that reports and never
decides — and the answer is yes on every axis that was measured:

* **The two rows M1 named as its job description moved.** `pydrop` and
  `fileclient/byfile-unknown` went from `silent` to `seen` in **all three
  filter modes**, on the strength of one sensor event kind the external
  stack does not have: the content of a small file read into a process.
  `delete-rename` and `cred-read` moved too. Of the 14 silent cells of the
  five gap rows (`uring`, `delete-rename`, `byfile-unknown`, `pydrop`,
  `cred-read`), the sensor moved **11 to seen**; the 3 `io_uring` cells
  stay silent, because a ring operation never crosses libc.
* **The semantic gain is one number: 98 %.** On the benign corpus, 1205 of
  1231 interesting actions the sensor reported are invisible to argv; argv
  sees only the 26 execs.
* **The interruption budget holds.** The corpus with the sensor active ran
  with zero questions in all three modes, and sensor silence — keyed to the
  instances the harness installed — fired zero times. A stopped instance is
  detected (the positive control), so the zero is a measurement, not a
  vacuous pass.
* **The overhead is bounded.** 1.46×/1.77×/1.42× (W1/W2/W3) standalone, and
  ×1.29/×1.13/×1.25 on top of the product posture.

Nothing here changes the rule the decision log already binds: the sensor is
not a boundary, and no allow decision may rest on anything it reports.

## What shipped

| file | what it is |
| --- | --- |
| `shim.c` / `build.sh` → `libafsensor.so` | the LD_PRELOAD shim: interposes the exec family, `open`/`openat`/`fopen`/`creat`, `read`/`fread`/`fgets`, `unlink`/`unlinkat`/`rmdir`, `rename`/`renameat`/`renameat2`, `connect`, `dlopen`/`dlmopen`, `setenv`/`unsetenv`/`putenv`; emits af-core `Event` JSON lines; registers every instance durably |
| `reader.py` | validates a sensor trace with the product's own reader (`agent-firewall tree`), prints the event histogram, computes the semantic gain, and checks sensor silence against the registration record |
| `run.sh` | the self-check: every event family, schema validation, the silence positive control (a SIGSTOPped instance must fire) |
| `research/bypass/run.sh` | the [af-1] matrix re-run with the shim active (the preload pass), classified in `research/bypass/classify.py` with sensor witness rules |
| `run-corpus.sh` | the benign corpus under the sensor: the gain run (sensor only) and the quiet gate (product posture, sensor active, all three modes) |
| `bench.sh` | overhead on the shared benchmark: baseline, sensor, product, product + sensor |

The af-core schema gained five kinds the sensor needs and the shipped
monitor does not produce: `file_read` (content capture), `file_delete`,
`file_rename`, `library_load`, `env_change`. They are additive; no rule
matches them yet, and the shipped monitor still holds no delete and no
rename.

## The event contract

Every line of a sensor trace is an af-core `Event`. The check is not a
re-implementation: `agent-firewall tree <trace>` reads every line with the
product's own deserializer and fails on any broken line. All 33 sensor
traces of the preload matrix pass it, and so do the corpus traces.

* **Exec events are intent.** They are written *before* the call, with the
  target path, argv, ppid, start_ticks and cwd — the about-to-exec fact an
  outside observer cannot have. An exec that then fails still leaves its
  event.
* **Everything else is post-hoc.** File opens, deletes, renames, connects,
  dlopen and environment changes are written only after the real call
  succeeded, so they describe actions that happened.
* **Content capture is bounded.** A regular file of at most 4096 bytes that
  a process reads captures at most 256 bytes per file, only if the chunk is
  valid text, never from `/proc`, `/sys` or `/dev`. Standard input captures
  at most 4 reads. A binary chunk captures nothing.
* **Paths are resolved.** Relative paths are joined with the working
  directory, so the trace is comparable across processes.

## The registration record (the B.5 fact)

Each instance appends `sensor_register` (instance id, pid, ppid, exe,
session, time) to the file named by `AF_SENSOR_REG`, refreshes
`sensor_heartbeat` about once per second while it lives **and talks**, and
appends `sensor_exit` at the end. Every write is one raw `write` to an
`O_APPEND` descriptor: no user-space buffer, so the record survives the
death of the writing process — measured in the kill-monitor run, where the
monitor's own buffered recorder left one line and the sensor trace kept
**37 events** with the registration record intact. That is the durability
failure of M1, answered at the sensor layer, and the instance list M4/M5
key on.

Heartbeats come from a thread that starts lazily, on the first event, so a
process that never reports anything never pays for a thread — and never
looks silent. An instance is *silent* only when its pid still lives, it
spoke at least once (an event or a heartbeat), and nothing arrived for
3 s. The positive control proves the check fires: a SIGSTOPped python
instance is reported at ~5 s stale, while the corpus produces zero.

Numbers: 102 instances registered in the corpus run (5 heartbeats — only
long-lived talkers need them), 6997 instances in the bench run, 23 612
events, 301 registration lines across the 33 matrix cells.

## The matrix re-run (the preload pass)

Product posture plus the shim, all three filter modes, witness from either
trace. The shim never holds; a hold can only come from the product. Full
table: `research/bypass/results/matrix.md` (`./research/bypass/run.sh`).

| row | builtin | with sensor | how |
| --- | --- | --- | --- |
| pydrop / script-content | silent ×3 | **seen ×3** | `file_read` of `drop.py` carries `DROP DATABASE customer_prod` — the interpreter's real name never mattered |
| fileclient / byfile-unknown | silent ×3 | **seen ×3** | `file_read` of `drop.sql` carries the same |
| delete-rename | silent ×3 | **seen ×3** | `file_delete` of `victim/f`, `file_rename` of `victim`→`moved` — kinds the schema now has |
| cred-read / read | silent (w-o, off), seen (a-o) | **seen ×3** | the read-open is visible to the sensor in every mode |
| uring | silent ×3 | silent ×3 | a ring operation never crosses libc; only a kernel mechanism sees it |
| static-file-net / rawsys (off) | silent | silent | a static binary never loads the shim; `syscall()` never calls the interposed symbols |
| kill-monitor / kill | silent, fail-closed | silent, fail-closed | the `/proc` scan is visible to the sensor; the `kill()` is not in the hook set, and the fail-closed outcome is unchanged |
| byfile-psql | held ×3 | **held ×3** | the product held it; the sensor adds no holds |

## The quiet gate (the corpus)

* **Zero questions.** The corpus under the product posture with the sensor
  active: `questions=0`, fw exit 0, session exit 0 in `write-only`,
  `all-opens` and `off`. The sensor asks nothing; that is its contract.
* **Zero sensor silence.** Every registered instance of every corpus run
  ended (`sensor_exit`) or is dead; none froze while alive.
* **Schema valid.** Every corpus sensor trace reads as af-core events.

## The semantic gain

Corpus under the sensor alone (no firewall, so no monitor noise): 3280
events, of which 1231 are interesting — 26 execs, 113 write-intent opens,
860 content captures, 95 deletes, 18 renames, 30 dlopens, 89 environment
changes, 0 connects (the corpus is offline), 0 stdin feeds. argv describes
only the execs: **1205 of 1231 (98 %) are invisible to argv**. The single
largest class is content: what a running process reads, which is exactly
the half of the pydrop/byfile gap the name lists could not close.

## The overhead

Shared benchmark, medians of 7, same session (load 1.8–3.9):

| configuration | W1 exec | W2 file | W3 mixed | factor W1/W2/W3 |
| --- | ---: | ---: | ---: | --- |
| no monitor | 147 ms | 13 ms | 83 ms | 1.00× / 1.00× / 1.00× |
| sensor alone | 215 ms | 23 ms | 118 ms | 1.46× / 1.77× / 1.42× |
| product (write-only) | 347 ms | 143 ms | 248 ms | 2.36× / 11.0× / 2.99× |
| product + sensor | 447 ms | 162 ms | 310 ms | 3.04× / 12.5× / 3.73× |

The sensor on top of the product multiplies by ×1.29 / ×1.13 / ×1.25. The
baseline matches the August baselines spike (147/13/83 against 148/14/83),
so the machine is comparable; the product row today is higher than that
spike's (252/54/147) — a busier machine and a pack that has since grown to
144 rules — which is why the factors, not the milliseconds, are the
comparison. The sensor costs more than the August log-only preload
(1.27×/1.29×/1.23×) because it does more: registration, heartbeats, one
`fstat` per open and the content capture. In the combined runs the shim
also instruments the monitor itself (the harness exports the preload to
the whole launcher); an M4/M5 integration that passes the preload at the
session root only removes that share, so ×1.29/×1.13/×1.25 is an upper
bound.

## The honest limits

Measured or observed in this run, none new to the direction:

* **Everything the baselines spike measured still bypasses it**: static
  binaries, raw `syscall()`, `io_uring`, and `env -u LD_PRELOAD` — the last
  one is the tamper signal M4 keys on, now with a registration record to
  key it to.
* **`posix_spawn` hides the about-to-exec fact.** An exec through
  `posix_spawn`'s internal path never crosses the interposed `execve`, so
  the parent emits no exec event; the child still registers and reports
  its own actions (measured: `/bin/true` spawned by Python registered and
  exited, with no exec event; bash's `fork`+`execve` children did emit).
* **A quiet process is not a silent sensor.** Only an instance that spoke
  and then froze while its process lives is silent. A process that never
  reported anything is the normal foreign-process case the decision log
  says must never fire.
* **The content capture sees secrets.** The cred-read run captured the
  (planted, fake) credential file verbatim. A sensor trace must be handled
  like the product trace: a log with private data. Redaction-by-design is
  M6 work and applies to sensor traces from the start.
* **`execvp` events carry no exe**, only the name and argv, because the
  search path resolves inside the real call.
* **The heartbeat thread is detached** and dies with the process; a
  heartbeat line can race process teardown. The record is append-only, so
  the worst case is a trailing heartbeat, never a corrupted line.

## Gate decision

**Keep the sensor in the product plan, as a sensor.** The evidence: 11 of
14 gap cells moved to seen, 98 % semantic gain, zero questions, zero
silence, ×1.13–×1.29 on top of the product. The demote option was live and
is declined on these numbers. What ships forward is the spike plus the
schema kinds; product integration (the monitor passing the preload at the
session root, correlation against the registration record) is M4/M5 work,
and every integration still obeys the two standing rules: the sensor never
decides, and sensor silence keys on the instances the firewall itself
installed.
