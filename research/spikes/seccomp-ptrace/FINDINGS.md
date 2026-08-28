# Spike: seccomp with ptrace (`SECCOMP_RET_TRACE`)

Date: this spike. Machine: Fedora 43, kernel 7.0.9-105.fc43.x86_64, x86_64,
uid 1000, no root, no `sudo`. All code is in this directory. Every number
below comes from a command that I ran on this machine.

## Verdict

**Yes. The hybrid closes the gap, and the price is acceptable.** A `seccomp`
filter that returns `SECCOMP_RET_TRACE` for a small set of calls gives
`af-monitor` file and network visibility for 1.16× to 1.92× of the wall-clock
time of the workload, against 3.0× to 10.1× for full `strace`. The product
filter (`openat` for change, `unlinkat`, `renameat2`, `connect`, plus
`openat2`) costs 1.16×, 1.33× and 1.22× on the three harness workloads when
the kernel can decide from the `flags` argument. It keeps every part of the
shipping design: the same `ptrace` session, the same `PTRACE_EVENT_EXEC`,
`PTRACE_EVENT_FORK` and `PTRACE_O_EXITKILL`, and the same descendant
tracking. The filter is inherited by children and it survives `execve`, so
the supervisor installs it once at the session root and sees the whole
process tree. The cost model is simple and it predicts well: **the cost is
the number of supervisor stops multiplied by about 7 µs**. The curve turns
bad at exactly one place — where the kernel can no longer decide from a
scalar argument. A BPF filter cannot read a path, so a rule about a path
needs every open to reach the supervisor: 1034 stops instead of 3 on the file
workload, and 1.92× instead of 1.33×. That is still a good price. Two things
stay out of reach and I state them plainly: content inside an open file
descriptor costs 8.8× and is not worth it, and a rule about a path is **not
safe** against a target with two threads, because I won that race in 2 to 14
tries.

## What I ran

I wrote a supervisor in C (`src/hybrid.c`, `src/filter.c`), a probe for
`no_new_privs` (`src/nnp_probe.c`) and a small target program
(`src/victim.c`). One command builds and runs everything:

```sh
make check
```

* `./tests/run-tests.sh` — 14 test groups, **61 checks, 0 failures**. Every
  claim below traces to one of them.
* `./bench/run-bench.sh` — timing through the shared harness
  `research/bench/bench.sh`, which is the harness that produced the numbers
  in `docs/RESEARCH.md`.
* `./bench/count-stops.sh` — the exact number of supervisor stops for each
  workload and each filter. These counts are deterministic.
* `./bench/write-cost.sh` — the price of tracing `write`.

I ran the harness with `--runs 15`. I ran three passes for the configurations
`x`, `z`, `a`, `b`, `e`, `w` and the two `strace` references, four passes for
`f` and `g`, and five passes for `c` and `d`. The table gives the median of
the pass medians.

Two notes about the method:

* The harness makes its work directory with `mktemp -d`. I did **not** set
  `TMPDIR`. The default directory is a tmpfs. When I moved it to the project
  file system, the file workload went from 12 ms to 24 ms and no longer
  matched the documented baseline.
* The workloads W1 and W3 start many programs, so their medians move by about
  ±10 % between passes. The stop counts do not move at all. Read the stop
  counts as the explanation and the times as the effect.

## The cost curve

Median wall-clock time in ms. The factor against the baseline is in
brackets.

| Wrapper | W1 exec | W2 file | W3 mixed |
| --- | --- | --- | --- |
| none (baseline) | 148 | 12 | 82 |
| (x) `af-monitor` today: `ptrace` exec events, no filter | 165 (1.11×) | 15 (1.25×) | 97 (1.18×) |
| (z) a filter that traces nothing | 168 (1.14×) | 16 (1.33×) | 99 (1.21×) |
| **(a) `execve`** | **173 (1.17×)** | **15 (1.25×)** | **98 (1.20×)** |
| **(b) `execve` + `openat` for change only** | **173 (1.17×)** | **15 (1.25×)** | **99 (1.21×)** |
| **(c) `execve` + every `openat`** | **181 (1.22×)** | **27 (2.25×)** | **114 (1.39×)** |
| **(d) (c) + `unlinkat` + `renameat2` + `connect`** | **178 (1.20×)** | **24 (2.00×)** | **108 (1.32×)** |
| (f) (d) without `execve` — the product filter | 178 (1.20×) | 23 (1.92×) | 106 (1.29×) |
| (g) (f) but only the opens for change | 171 (1.16×) | 16 (1.33×) | 100 (1.22×) |
| (w) `write` + `writev` + `sendto` + `sendmsg` + `connect` | 167 (1.13×) | 19 (1.58×) | 96 (1.17×) |
| **(e) full `PTRACE_SYSCALL`, my code, no filter** | **327 (2.21×)** | **77 (6.42×)** | **210 (2.56×)** |
| reference: `strace -f -qq` | 449 (3.03×) | 121 (10.1×) | 271 (3.30×) |
| reference: `strace -f -qq --seccomp-bpf -e trace=execve` | 215 (1.45×) | 16 (1.33×) | 111 (1.35×) |

My own numbers agree with the numbers in the task. My full `PTRACE_SYSCALL`
row (6.42× on W2) is a little faster than `strace` (10.1×) because I do not
decode or print anything.

### Why the curve has that shape

The exact number of times the supervisor woke up:

| Config | W1 exec | W2 file | W3 mixed |
| --- | --- | --- | --- |
| (a) `execve` | 301 | 3 | 121 |
| (b) + `openat` for change | 302 | 6 | 182 |
| (c) + every `openat` | 915 | 1037 | 1275 |
| (d) + delete, rename, connect | 915 | 1037 | 1275 |
| (f) the product filter, no `execve` | 614 | 1034 | 1154 |
| (g) (f) with opens for change only | 1 | 3 | 61 |
| (w) `write` and friends | 0 | 500 | 60 |
| (e) full `PTRACE_SYSCALL` | 35335 | 13697 | 21715 |

The two tables tell the same story. On W2, configuration `g` makes 3 stops
and costs 1.33×. Configuration `f` makes 1034 stops and costs 1.92×.
Configuration `e` makes 13697 stops and costs 6.42×.

From these pairs the cost of one stop is **about 5 µs to 10 µs**. The
reference from full tracing agrees: on W2, `(77 − 12) ms / 13697 stops` is
4.7 µs per stop, and `PTRACE_SYSCALL` makes two stops for each call.

**The curve turns where the number of stops turns**, and nowhere else. Adding
`unlinkat`, `renameat2` and `connect` to `openat` (from `c` to `d`) is free,
because those calls are rare: 1037 stops in both. Adding read-only `openat`
(from `b` to `c`) costs a factor of 170 in stops, because every program opens
libraries, locale files and configuration files.

I also measured the price of the filter itself. Configuration `z` installs a
filter in which every rule says `ALLOW`. It costs 168/16/99 against 165/15/97
for no filter at all. The BPF program is close to free; only the stops cost.

Path reading is also close to free. I ran configuration `f` with and without
`--no-paths` over two passes: 188/183 against 171/167 on W1, 25/25 against
23/24 on W2, 121/104 against 98/106 on W3. The W3 difference is noise. One
warm `pread` on `/proc/<pid>/mem` costs about 1 µs to 2 µs.

## Filter inheritance across fork and exec

**Both are true. This is the most important result for the product.**

Test `filter_survives_fork_and_exec` runs
`sh -c 'sh -c "cat file"'` under the supervisor.

* **Across `execve`:** the log holds three `exec` events with the same pid,
  and the supervisor still gets seccomp stops after the third one. The filter
  is not removed by `execve`.
* **Across `fork`:** the log holds seccomp stops with a pid that is not the
  pid of the root. The child never installed a filter of its own. It got the
  filter from its parent.

The consequence for the product is direct. `af-monitor` installs the filter
**one time**, in the `pre_exec` closure of `run()`, next to the existing
`ptrace::traceme()` call. Every child, every grandchild and every new program
in the session then carries the filter. There is no per-process setup, no
race with a fast `fork`, and no way for a descendant to escape. This is the
same guarantee that `PTRACE_O_TRACEFORK` gives for the ptrace session, and it
comes free.

## Can it block

Yes. At a `PTRACE_EVENT_SECCOMP` stop the kernel has not run the call yet.

The supervisor reads the registers with `PTRACE_GETREGSET(NT_PRSTATUS)`, sets
`orig_rax` to `-1` and `rax` to `-EPERM`, and writes them back with
`PTRACE_SETREGSET`. The value `-1` is important: any other value in `orig_rax`
makes the kernel run the filter a second time (`recheck_after_trace`), and
`-1` makes it skip the call.

Test `the_supervisor_can_refuse_a_call`:

* `rm` on a file under `--block unlinkat` gives exit code 1, prints
  "Operation not permitted", and **the file is still on disk**. The test
  asserts the file exists.
* The counter `blocked=1` appears in the statistics.
* Without the block, the same command deletes the file. So the test measures
  the block and not a broken setup.

The block also works with a condition. `--block-path <text>` refuses only when
the path holds that text. One file is deleted and the protected file stays.
But read `## What a BPF filter cannot test` before you trust that.

The supervisor is transparent when it allows. Test
`the_supervisor_keeps_the_result_of_the_target`: the exit code 42 and the
standard output of the target both pass through unchanged.

## What a BPF filter cannot test

A BPF filter runs in the kernel with no access to user memory. It can test a
**scalar** argument. It cannot follow a **pointer**. So it can test the
`flags` of an `openat`, but it can never test the **path**.

This one limit sets the whole cost curve.

* **When flags are enough, the kernel drops almost everything.** My rule
  `flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)` cut W2 from 1034 stops
  to 3. That is 99.7 % of the open traffic that the supervisor never sees.
  The cost falls from 1.92× to 1.33×.
* **When a rule needs a path, the kernel drops nothing.** A policy such as
  "warn when the agent reads `~/.ssh/id_rsa`" needs the path of a read-only
  open. The filter must then send every `openat` to the supervisor. That is
  the jump from 3 stops to 1034 stops, and the price of that policy on W2 is
  1.33× → 1.92×.

So the answer to "how much of the file traffic can the kernel drop" is: **all
of it or none of it**, and the switch is whether the policy needs a path.
1.92× is still far better than 10.1×, so a path policy is affordable. But the
product should let a policy declare that it only cares about writes. Then the
kernel does the work.

`openat2` shows the limit at its worst. It puts its flags inside a
`struct open_how` **behind a pointer**. The kernel cannot classify it at all.
Every `openat2` must reach the supervisor. Test
`openat2_needs_the_supervisor`: the filter labels it with its own group, and
the supervisor reads `how_flags=0x41` out of `/proc/<pid>/mem`. glibc uses
`openat` today, so this is rare, but a program that calls `openat2` directly
pays the full price and there is no filter trick that helps.

**The pointer limit also breaks path-based blocking, not only path-based
speed.** The supervisor reads the path from tracee memory at the stop. The
kernel reads the same memory a second time when the call really runs. A
second thread can change the buffer between the two reads.

Test `a_second_thread_defeats_a_path_rule` builds exactly that. The target
has two threads. One thread calls `unlinkat` on a shared buffer. The other
thread writes a harmless path and the protected path into that buffer in a
loop. With `--block unlinkat --block-path race-bbb`:

```
race tries=3  deleted=2  target_gone=1
```

**The protected file was deleted.** I ran it six times: the race was won
after 2, 3, 3, 5, 6 and 14 tries. It is not a rare event.

The same test then removes the path condition and blocks the call by its
number alone:

```
race tries=2000 deleted=0 target_gone=0   (blocked=2000)
```

**That block holds.** No file was deleted in 2000 tries.

The rule for the product is therefore hard:

* A decision that uses only the **call number** or a **scalar argument** is
  sound. The value cannot change after the stop.
* A decision that uses a **path** or any other pointer argument is sound for
  **reporting**, and sound enough for a single-threaded target, but it is
  **not** a security control against a target that wants to defeat it.

`SECCOMP_USER_NOTIF` has the same race. It is a property of every supervisor
that reads a path out of the memory of the target.

## no_new_privs and setuid

**`no_new_privs` IS required.** I tested the claim that it is not, and the
claim is wrong.

Test `the_filter_needs_no_new_privs`, from `build/nnp-probe --check`:

* Without `PR_SET_NO_NEW_PRIVS`, `seccomp(SECCOMP_SET_MODE_FILTER, ...)`
  returns **EACCES (errno 13)**.
* With `PR_SET_NO_NEW_PRIVS`, the same call succeeds.

The kernel only lets you skip `no_new_privs` when you have `CAP_SYS_ADMIN`,
and this product runs as a normal user.

**But it costs nothing extra, because `ptrace` already does the same thing.**
Test `no_new_privs_costs_nothing_extra` runs `passwd -S $USER` and counts the
fields of the answer. `passwd` is setuid root.

| Setup | Fields in the answer |
| --- | --- |
| plain shell, no monitor | 7 (the setuid worked) |
| `PR_SET_NO_NEW_PRIVS` only | 2 |
| `ptrace` only (config `x`, no filter, no `no_new_privs`) | 2 |
| the hybrid (`ptrace` + filter + `no_new_privs`) | 2 |

The kernel drops the setuid bit for any process that a normal user traces.
`af-monitor` already loses setuid today. The log of the hybrid confirms it
with `exec pid=… euid=1000` when it runs setuid `/usr/bin/passwd`.

So the honest statement is: `no_new_privs` **is** needed, and it changes
**nothing** that `ptrace` had not already changed. The behaviour of
`af-monitor` for setuid binaries does not get worse.

## Robustness and restart

**`PTRACE_O_EXITKILL` still protects the machine.** Test
`exitkill_stops_the_target_when_the_supervisor_dies` uses `--die-after 28`,
so the supervisor calls `_exit(70)` while the target waits at a seccomp stop.
The target had printed 11 lines. Three seconds later it had still printed 11
lines, its marker file was never created, and every pid from the log was
gone. A target that waits at a `PTRACE_EVENT_SECCOMP` stop is not a special
case: the kernel kills it with the rest of the tree.

**Detach and re-attach is a negative result. Read this before you plan a
restart feature.**

Test `the_filter_survives_a_detach` uses `--detach-after 6 --reattach-ms 400`.
The result was `ok=33 enosys=7`.

* The good part: the filter lives in the target, not in the supervisor. It
  survived `PTRACE_DETACH`. After `PTRACE_ATTACH` and a new
  `PTRACE_SETOPTIONS` with `PTRACE_O_TRACESECCOMP`, the stops came back and
  the calls worked again.
* The bad part: **during the gap, every traced call failed with `-ENOSYS`.**
  `SECCOMP_RET_TRACE` with no tracer does not mean "allow". It means "skip
  the call and return `-ENOSYS`". The 7 failures are the opens that happened
  while the supervisor was away.

So the target is not merely unobserved during a restart. It is **broken**.
A firewall restart would make the agent see "Function not implemented" from
random opens. The product cannot restart the supervisor under a live filter
without more work. Two ways out exist, and I did not build either: hand the
`ptrace` session to a second supervisor process before the first one leaves,
or accept that a restart kills the session, which `PTRACE_O_EXITKILL` already
does anyway.

There is one more trap that the product must know. **`SECCOMP_RET_TRACE`
returns `-ENOSYS` before the supervisor has set `PTRACE_O_TRACESECCOMP`.**
The supervisor can only set that option at a ptrace-stop. The first stop is
the `SIGTRAP` after the first `execve` — the child must not raise `SIGSTOP`,
for the deadlock reason in `docs/RESEARCH.md` section 3. So a filter that
traces `execve` breaks its own `execve`. I measured it:
`--direct --config a` gives exit 127 and "Function not implemented".

The spike solves it in two ways. The default way execs a stage two through
`/proc/self/exe`, so the supervisor gets a stop before the filter exists.
The better way, and the one the product should use, is to **leave `execve`
out of the filter**. `af-monitor` gets exec from `PTRACE_EVENT_EXEC` already.
Configurations `f` and `g` do this and run with `--direct`, with no stage two
and no extra exec.

## The migration path for af-monitor

The change is small, because the hybrid extends the shipping design instead
of replacing it.

### What changes in `crates/af-monitor/src/tracer.rs`

| Item | Change |
| --- | --- |
| `TRACE_OPTIONS` (line 27) | Add `PTRACE_O_TRACESECCOMP`. One line. The other six options stay. |
| `run()` (line 64) | In the existing `pre_exec` closure, install the `seccomp` filter after `ptrace::traceme()`. Set `PR_SET_NO_NEW_PRIVS` first. The filter must not hold `execve`; then no stage two is needed. |
| `handle_ptrace_event()` (line 202) | Add one branch for `PTRACE_EVENT_SECCOMP` (value 7) that calls a new `handle_seccomp()`. |
| `adopt()` (line 311) | No change. It already sets `TRACE_OPTIONS` on a process that it finds, and the new option comes with it. |

### What stays the same

`await_root_start()` (line 140), `dispatch()` (line 174), `handle_exec()`
(line 251), `note_child()` (line 342), `note_exit()` (line 362), `resume()`
(line 377), `kill_one()`, `stop_for_ever()`, `kill_tree()`, `depth()`,
`ancestry()`, `emit()`, `outcome()`, `wait_any()`, `forwardable()` and
`decode_status()` all stay as they are. The descendant tracking, the exec
decision point and the whole event model do not move.

### What is new

* `handle_seccomp(pid)` — a sibling of `handle_exec()`. It reads the group
  number with `PTRACE_GETEVENTMSG`, reads the arguments with
  `PTRACE_GET_SYSCALL_INFO`, reads pointer arguments through
  `/proc/<pid>/mem`, asks the handler, and then either resumes or refuses.
* A small module for the filter and for register and memory access. My
  `src/filter.c` is about 200 lines and `nix` already wraps most of the
  ptrace side.
* `MonitorHandler::on_syscall(...)` in `crates/af-monitor/src/lib.rs`, beside
  the existing `on_exec()` (line 170).
* A new `Intercept` variant, for example `Refuse`. Today `Intercept::Deny`
  (line 121) sends `SIGKILL`. That is right for an exec and wrong for a
  syscall: the correct answer for a blocked `openat` is `-EPERM`, so the
  program can handle the error like any other permission error.
* `impl MonitorHandler for FirewallHandler` in `crates/af-cli/src/run.rs`
  (lines 336-392) gets an `on_syscall` next to its `on_exec`. It can reuse
  `evaluate`, `ancestry_of`, `emit` and the approval flow without change.

### What the product gets

`af_core::EventKind::FileOpen { path, write }` and
`EventKind::NetworkConnect { addr, port, host }` already exist in
`crates/af-core/src/event.rs` (lines 135-148) and nothing emits them today.
`handle_seccomp()` emits both. The delete and rename groups need one new
`EventKind`.

The policy side needs **no change at all**. `af_core::Action::FileOpen` and
`Action::NetworkConnect` already exist in `crates/af-core/src/process.rs`
(lines 158-170), and `crates/af-policy/src/matcher.rs` (lines 466-473)
already binds the subjects `path`, `write`, `host`, `addr` and `port`. The
policy engine is waiting for these events.

### The filter that I recommend

Start with configuration `g`: `openat`/`open` when the flags ask for a
change, `openat2` (always, see the pointer limit), `unlinkat`, `unlink`,
`renameat2`, `rename` and `connect`. No `execve`. Measured cost: **1.16×,
1.33×, 1.22×** on the three workloads. Move to configuration `f` (every
open) only when a policy needs the path of a read, and pay 1.92× on a
file-heavy workload.

## What it cannot do

* **It cannot see content inside a file descriptor that is already open.**
  This is the exact example in `docs/PRODUCT.md`: a Python script that
  deletes rows through a library. The `connect` is visible. The SQL text is
  not, because it goes out through `write` or `sendto` on an open socket.
  Tracing those calls is possible but it is too slow. `./bench/write-cost.sh`
  on a program that writes 20000 times: no monitor 18 ms, configuration `g`
  22 ms (1.2×), configuration `w` with `write` and `sendto` **159 ms (8.8×)**,
  full tracing 391 ms (21.7×). 8.8× is the same order as the full
  `PTRACE_SYSCALL` that we already rejected. A chatty program pays it in
  full. To see content the product needs a different tool, such as a proxy
  for the protocol.
* **A rule about a path is not a security control.** See the race above. It
  is good for reporting and for an honest program. A target with two threads
  defeats it in a few tries. Only rules about the call number and about
  scalar arguments are sound.
* **A restart breaks the target.** During a detach, every traced call returns
  `-ENOSYS`. See `## Robustness and restart`.
* **`no_new_privs` is required.** A setuid program loses its setuid bit. This
  is not new — `ptrace` already did it — but the product cannot offer a mode
  that keeps setuid.
* **The filter is x86_64 only in this spike.** The prologue checks
  `AUDIT_ARCH_X86_64` and allows everything else, and it allows the x32 ABI
  (`nr >= 0x40000000`). A product filter must handle each architecture that
  it supports, or deny the unknown ones. The syscall numbers differ per
  architecture, so the rule table is not portable.
* **The filter cannot be changed after `execve`.** `seccomp` filters only
  stack; you cannot remove one. A policy reload during a session cannot make
  the filter narrower. It can only make the supervisor ignore more stops,
  which costs the stop but not the decision. Plan the filter for the widest
  policy that the session may load.
* **It still cannot see what the program does with no syscall.** Pure
  computation, memory writes and anything inside the process stay invisible.
  That limit is the same as for every syscall-level tool.
* **It does not decode the arguments of every call it traces.** My supervisor
  reads paths, `openat` flags, and the address and port of `connect` for
  AF_INET and AF_INET6. Anything else needs more code, and each new pointer
  read adds about 1 µs to 2 µs per stop.
