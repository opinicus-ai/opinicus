# Baselines: what the cheap mechanisms cost, and what they miss

Spike: `research/spikes/baselines/`.
Machine: Fedora 43, kernel 7.0.9-105.fc43.x86_64, x86_64, uid 1000, no root,
no `sudo`, `yama/ptrace_scope = 0`, `kernel.unprivileged_bpf_disabled = 2`.
Every number below comes from a file in `results/`. Re-run with `./run-all.sh 15`.

## Verdict

Two of the four cheap mechanisms cannot carry a security decision, and the
numbers are not close. `/proc` polling missed **99.7 %** of the processes in
the standard exec workload at every period that was tested, including 10 ms,
and it can never block, because it learns about a process only after that
process already ran; it is a telemetry tool, not a control point.
`LD_PRELOAD` can block — the deny test stopped a dynamic program — but it is
advisory: four measured gaps let an ordinary program pass unseen, and the
cheapest of them (`env -u LD_PRELOAD`) is one word long, so it cannot carry a
decision either. Exec-only `ptrace`, the shipping approach, is the right
choice: it saw 301 of 301 processes with no race, it blocked at the exec stop,
and the mechanism itself is nearly free at **0.042 ms per new process** — the
shipping monitor's 1.7× on W1 is mostly its own work, not `ptrace`. Its limit
is real and large: a workload that removed a directory tree, removed a file
and opened a TCP connection inside one running Python process produced a trace
with **zero** matching events, while all three actions completed. Full
`PTRACE_SYSCALL` closes that gap and blocks everything an unprivileged target
does, except vDSO calls and writes through a shared mapping, for 2.3–2.4× on
realistic workloads and ~5 µs for each stop; that is the honest price of
in-process visibility with no privileges.

## What I ran

I built four monitors and a set of workloads in C, Python and Go. Nothing
needs root. Nothing is destructive: the action of every coverage test is a
marker file in `scratch/`, and the network test uses a listener that the test
starts itself on `127.0.0.1`.

| Tool | File | What it is |
| --- | --- | --- |
| `procpoll` | `src/procpoll.c` | walks `/proc` at a fixed period, rebuilds the tree from `ppid`, keys each process on (pid, start time) |
| `libafwpreload.so` | `src/preload.c` | wraps `execve`, `openat`, `unlink`, `connect`, forwards with `dlsym(RTLD_NEXT, ...)`, with a deny mode |
| `ptrace_full` | `src/ptrace_full.c` | own tracer; `--mode syscall` stops at every call, `--mode events` stops only at fork/exec/exit, `--deny` refuses named calls |
| `selfcheck` | `src/selfcheck.c` | prints `TracerPid`, `Seccomp`, `Seccomp_filters`, `LD_PRELOAD` and the injected maps |
| shipping monitor | `target/release/agent-firewall` | exec-only `ptrace`, built with `cargo build --release` |

Measurements, each with the shared harness or a script of this spike:

| Script | Result file | What it measures |
| --- | --- | --- |
| `scripts/bench-all.sh 15` | `results/bench.txt` | `research/bench/bench.sh --runs 15` for every wrapper |
| `scripts/startup-cost.sh` | `results/startup-cost.txt` | the fixed cost of one session, target `/bin/true`, 11 runs |
| `scripts/per-exec.sh` | `results/per-exec.txt` | splits the cost into a fixed part and a per-process part |
| `scripts/cpu-cost.sh` | `results/cpu-cost.txt` | the processor share of the poller |
| `scripts/syscall-rate.sh` | `results/syscall-rate.txt` | the cost of one `ptrace` system call stop |
| `scripts/gap-polling.sh` | `results/gap-polling.txt` | how many processes the poller never sees |
| `scripts/gap-preload.sh` | `results/gap-preload.txt` | the structural gaps of `LD_PRELOAD` |
| `scripts/gap-inprocess.sh` | `results/gap-inprocess.txt` | the in-process gap of the shipping monitor |
| `scripts/gap-syscall.sh` | `results/gap-syscall.txt` | whether full `PTRACE_SYSCALL` has a gap |
| `scripts/blocking.sh` | `results/blocking.txt` | whether each mechanism can stop an action |
| `scripts/visibility.sh` | `results/visibility.txt` | what a target can learn about its monitor |

Two measurement mistakes were found and corrected during the spike. They are
recorded here because a reader who repeats the work will meet them.

1. A poll loop that sleeps for the whole period before it checks `waitpid`
   makes the wall-clock time of the wrapper equal to the poll period. The
   first sweep showed 213 ms for every workload under the 200 ms poller. That
   was exit latency, not overhead. The loop now blocks `SIGCHLD` and uses
   `sigtimedwait()` with the period as the timeout.
2. A search of a whole monitor log for the marker path gives a false hit,
   because the `execve` record carries that path as an argument. The gap
   scripts now search only action lines. For the same reason the in-process
   search skips the `session_start` line, whose capability text contains the
   words "connection" and "socket".

## The decision table

Costs are median wall-clock milliseconds, 15 runs each, from `results/bench.txt`.
The factor is against the baseline row of the same column.
W1 = 300 runs of `/bin/true`. W2 = a small file workload. W3 = 60 rounds of
`cat` and `grep`.

| Mechanism | W1 ms | W2 ms | W3 ms | Factor (W1 / W2 / W3) | Block or watch | Needs privilege | Survives `fork` | Survives `execve` | Measured coverage gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| none (baseline) | 148 | 14 | 83 | 1.00× / 1.00× / 1.00× | — | — | — | — | sees nothing |
| `/proc` polling, 10 ms | 154 | 18 | 91 | 1.04× / 1.29× / 1.10× | **watch only** | no | yes | yes | misses 99.7 % of short processes |
| `/proc` polling, 50 ms | 159 | 18 | 91 | 1.07× / 1.29× / 1.10× | **watch only** | no | yes | yes | misses 99.7 % of short processes |
| `/proc` polling, 200 ms | 158 | 17 | 90 | 1.07× / 1.21× / 1.08× | **watch only** | no | yes | yes | misses 99.7 % of short processes |
| `LD_PRELOAD` | 188 | 18 | 102 | 1.27× / 1.29× / 1.23× | block (advisory) | no | yes | **only while the environment allows it** | any static or raw-syscall program passes unseen |
| exec-only `ptrace` (shipping) | 252 | 54 | 147 | 1.70× / 3.86× / 1.77× | **block** | no | yes | yes | blind inside a program that already runs |
| exec-only `ptrace` (raw mechanism) | 161 | 16 | 91 | 1.09× / 1.14× / 1.10× | **block** | no | yes | yes | the same in-process gap |
| full `PTRACE_SYSCALL` | 337 | 76 | 201 | 2.28× / 5.43× / 2.42× | **block** | no | yes | yes | vDSO calls and writes through a shared mapping |

Notes that the columns cannot hold:

* **The two `ptrace` rows are the same mechanism.** The first is the shipping
  binary. The second is `ptrace_full --mode events`, which stops at the same
  places and does nothing else. The difference is the work of the firewall,
  not the cost of `ptrace`. See the split below.
* **"Block" is measured, not assumed** (`results/blocking.txt`). The shipping
  monitor with a spike rule refused the marker program and the file was never
  written; that measurement is the source of the "block" answer for both
  exec-only rows, because they are the same mechanism at the same stop. The
  `LD_PRELOAD` deny mode refused the same program, **but the same deny against
  a static build of the same program did nothing and the marker appeared.**
  `ptrace_full --deny openat` stopped both the dynamic and the static program.
  The poller has no deny mode to write: it observes state that already exists.
* **Fork and exec survival is measured**, not assumed. The ground truth in
  `results/gap-polling.txt` comes from `ptrace_full --mode events`, which
  reported exactly 301 of 301 processes on every run of W1 and 21 of 21 on
  every run of the slow workload. `LD_PRELOAD` survives `fork` because the
  mapping is inherited, and survives `execve` only while the variable stays in
  the environment and the program uses the dynamic linker; three one-line
  changes broke it (below).
* **No mechanism here needs a privilege.** Everything ran as uid 1000 with
  `ptrace_scope = 0`. eBPF was not tested, because
  `kernel.unprivileged_bpf_disabled = 2` closes it to an unprivileged user.

### Where the cost of the shipping monitor is

From `results/startup-cost.txt` and `results/per-exec.txt`:

| Monitor | Fixed cost of a session | Cost of one new process (W1) | Share of the W1 overhead that is fixed |
| --- | --- | --- | --- |
| exec-only `ptrace` (shipping) | **42.7 ms** | 0.204 ms | 41 % |
| exec-only `ptrace` (raw mechanism) | 0.2 ms | **0.042 ms** | 2 % |
| full `PTRACE_SYSCALL` | 0.4 ms | 0.627 ms | 0 % |
| `LD_PRELOAD` | 4.3 ms | 0.119 ms | 11 % |
| `/proc` polling, 10 ms | 5.1 ms | 0.003 ms | 85 % |

Two facts follow, and both matter for the product.

1. **The exec stop is nearly free.** The kernel mechanism costs 0.042 ms for
   each new process. The shipping monitor costs 0.204 ms, so about four fifths
   of the marginal cost is the firewall's own work — policy evaluation, the
   `/proc` reads for argv and cwd, and input capture.
2. **The fixed 42.7 ms is why W2 looks bad.** W2 is a 14 ms workload, so a
   fixed 42.7 ms turns into a 3.86× factor. The factor is honest, but it
   describes the start of the session, not the monitor's cost for each action.

The cost of full `PTRACE_SYSCALL` has a simple unit
(`results/syscall-rate.txt`): 5.23, 4.67 and 4.73 µs for each stop on W1, W2
and W3. **About 5 µs for each stop, two stops for each system call**, on
18 418, 6 854 and 11 158 calls. That number is stable across workloads, so the
cost of this mechanism can be predicted from the system call count of a
workload.

## The polling miss rate

From `results/gap-polling.txt`, 5 repeats for each period. Ground truth comes
from `ptrace_full --mode events`, which counted exactly 301 processes on every
W1 run and 21 on every slow run.

**W1 of the shared harness: 300 runs of `/bin/true`, each about 0.5 ms.**

| Period | Processes seen | Missed | **Miss rate** | Polls during the run |
| --- | --- | --- | --- | --- |
| 10 ms | 1 of 301 | 300 | **99.7 %** | 12 |
| 50 ms | 1 of 301 | 300 | **99.7 %** | 4 |
| 200 ms | 1 of 301 | 300 | **99.7 %** | 2 |

The one process that every period saw is the shell that runs the loop. **Not
one of the 300 children was ever seen, at any period.** The result was the
same on all 5 repeats: minimum 1, maximum 1.

**A slower workload: 20 runs of `/bin/sleep 0.05`, each about 50 ms.**

| Period | Processes seen | Missed | **Miss rate** |
| --- | --- | --- | --- |
| 10 ms | 21 of 21 | 0 | **0.0 %** |
| 50 ms | 19 of 21 | 2 | **9.5 %** |
| 200 ms | 3 of 21 | 18 | **85.7 %** |

The curve says the obvious thing exactly: a poller sees a process only when
the lifetime of the process is long against the period. A process that starts
and ends between two polls leaves no trace to poll. The lifetime of the
commands a coding agent runs is often under one millisecond, so no period that
a developer machine can afford will help.

Making the period shorter is not a way out, because the cost of a poll grows
with the size of the machine, not with the work of the target
(`results/cpu-cost.txt`, 377 processes on the machine, target `sleep 3`):

| Period | Polls | Processor time of the poller | For each poll | Share of one core |
| --- | --- | --- | --- | --- |
| 10 ms | 227 | 714.1 ms | 3.15 ms | **23.8 %** |
| 50 ms | 57 | 205.0 ms | 3.60 ms | 6.8 % |
| 200 ms | 16 | 55.7 ms | 3.48 ms | 1.9 % |

A quarter of a core, for a mechanism that still missed 99.7 % of the
processes. A shorter period does not exist as an option: one poll of this
machine took **3.15 ms**, so a 1 ms period cannot be met at all — the poller
would run without a pause and still be late. Polling is not a slow path to
the right answer; it is the wrong shape of answer.

## Coverage gaps

### `/proc` polling — the short-life gap

**Workload.** W1 of the shared harness: `sh -c 'while ...; do /bin/true; done'`,
300 times. Ground truth from `ptrace_full --mode events`.

**Result.** 99.7 % missed at 10 ms, 50 ms and 200 ms; see the table above.
The full log of the 10 ms poller for one W1 run holds exactly one line:

```
seen pid=1859382 starttime=369355777 comm=sh
```

**What this means.** The gap is structural, not a tuning problem. A poller
reads state that exists at the moment of the read. A process that has already
exited has no state to read. The mechanism also cannot block, for the same
reason: by the time the supervisor learns that `rm -rf` exists, `rm -rf` has
finished. This mechanism can count long-lived processes. It cannot support a
security decision.

### `LD_PRELOAD` — four structural gaps

**The control first.** A dynamic program that uses the libc wrappers was
recorded correctly: `openat`, `unlink` and `connect` all appeared in the log,
with the right path and the right port. So the interposer works.

| Case | Marker written | Action in the log | `execve` in the log | How likely by accident |
| --- | --- | --- | --- | --- |
| control, dynamic libc | yes | **recorded** | yes | — |
| **gap 1a**, own static program | yes | **NO RECORD** | yes | low for hand-written C |
| **gap 1b**, static Go program | yes | **NO RECORD** | yes | **high** |
| **gap 2**, `syscall(SYS_openat, ...)` | yes | **NO RECORD** | yes | low |
| **gap 3a**, `env -u LD_PRELOAD` | yes | **NO RECORD** | **no** | **high** |
| **gap 3b**, `LD_PRELOAD= cmd` | yes | **NO RECORD** | yes | **high** |
| **gap 3c**, `unset LD_PRELOAD` in a shell | yes | **NO RECORD** | yes | **high** |
| **gap 4**, a call outside the wrapper set | yes | **9 of 10 removals missed** | — | **certain** |

**Gap 1, a static program.** The static build has 0 `INTERP` segments in its
ELF header, so the dynamic linker never runs and the library is never mapped.
`gcc -static` fails on this machine (`glibc-static` is not installed and there
is no root), so the test uses two other static programs: a freestanding
`-nostdlib -static -no-pie` C program with raw `syscall` instructions, and a
static Go binary. Both wrote the marker with no record.

*How likely by accident:* **high, and higher than the raw count suggests.**
Only 2 of 2903 ELF files in `/usr/bin` on this machine are statically linked.
But those two are `/usr/bin/gh` and `/usr/bin/cloudflared` — and `gh` is a
tool that a coding agent runs constantly. Every Go and every Rust
`musl` binary has this shape: `kubectl`, `terraform`, `docker`, `ripgrep`
builds. `/usr/sbin/ldconfig` is static-pie. An agent does not need to try.

**Gap 2, a direct system call.** `marker_rawsyscall.c` calls
`syscall(SYS_openat, ...)`. The wrapper is a libc symbol, so nothing catches
the call. Marker written, no record.

*How likely by accident:* **low.** Ordinary C code uses the libc wrapper.
But a Go program does exactly this for every call, which folds this gap into
gap 1, and any program that wants to avoid the interposer needs one line.

**Gap 3, a changed environment.** `LD_PRELOAD` is ordinary process state.
Three one-word changes each broke the monitor completely. With `env -u` even
the `execve` disappeared from the log, because `env` removed the variable
before the target started.

*How likely by accident:* **high.** Build systems, test runners, `sudo`,
container entry points and language tool chains rewrite the environment as
normal work. A program does not have to be hostile to erase this monitor; it
has to be tidy.

**Gap 4, an incomplete wrapper set.** This one was not in the brief; the
in-process test found it. Against `workloads/inproc_gap.py`, the interposer
logged **1** removal. The system call tracer counted `unlink` = 1,
`unlinkat` = 8 and `rmdir` = 1 for the same workload. Python's `shutil.rmtree`
uses `unlinkat`, which the library does not wrap. **The interposer recorded 1
of 10 removal operations, and the 9 it missed are the ones that deleted the
tree.**

*How likely by accident:* **certain.** Linux has many ways to say the same
thing: `open`/`openat`/`openat2`, `unlink`/`unlinkat`, `rename`/`renameat`/
`renameat2`, `connect` after `socket`, plus `io_uring`, which needs no call at
all for each action. A wrapper list is a deny list of names, and a deny list of
names is never finished.

**Can it block?** Yes, but only where it is present. `AFW_PRELOAD_DENY`
refused the open and the marker was missing:

```
DENY openat pid=1768994 path=.../blocked-marker-preload.txt
```

The same deny against the static build of the same program did nothing, and
the marker appeared. A control that any program can remove by editing its own
environment is advisory. It is useful to reduce noise; it cannot be the thing
that stops a destructive command.

### Exec-only `ptrace` — the in-process gap

Measured in the next section, because it is the central result of this thread.

### Full `PTRACE_SYSCALL` — is there a gap at all?

**Workload.** `workloads/vdso_and_mmap.c`, run under
`ptrace_full --mode syscall`. It does two things and writes both results.

**Case 1, the vDSO.** The workload called `clock_gettime` **200 000** times.
The tracer counted:

```
clock_gettime  number=228  calls=0
gettimeofday   number=96   calls=0
time           number=201  calls=0
getcpu         number=309  calls=0
```

**Zero stops for 200 000 calls.** The kernel maps the vDSO into the process,
so those calls never enter the kernel. This gap is real but harmless: the vDSO
exposes only time and processor identity. Nothing destructive is in it.

**Case 2, a shared file mapping.** The workload opened a file, mapped it
`MAP_SHARED`, **closed the descriptor**, and then changed the file with a
`memcpy`. Afterwards the file held
`PAYLOAD-WRITTEN-THROUGH-A-SHARED-MAPPING`. The tracer counted `write` = 1
(that one is the `fprintf` to standard error), `pwrite64` = 0, `writev` = 0 and
`msync` = 0. **A store instruction changed a file with no system call, and the
descriptor was already closed when it happened.**

This gap matters more, and it is the honest limit of every system call
monitor, not only of `ptrace`. A monitor that stops at `openat` and `mmap` can
still see the intent — the file was opened for writing and mapped `MAP_SHARED`
before the descriptor was closed — so the policy point is the `mmap`, not the
write. But the write itself is invisible.

**Everything else was visible.** The same run counted 35 system calls in
total, and every one is accounted for in `results/gap-syscall.txt`: `mmap` 8,
`close` 3, `mprotect` 3, `openat` 3, `fstat` 2, `munmap` 2, `pread64` 2, and
one each of `read`, `write`, `brk`, `access`, `ftruncate`, `arch_prctl`,
`set_tid_address`, `exit_group`, `set_robust_list`, `prlimit64`, `getrandom`
and `rseq`. For an unprivileged target, no ordinary action other than the two
above avoided a stop.

## The in-process gap of the shipping approach

This is the most important measurement of the thread, so it is written to be
repeated: `./scripts/gap-inprocess.sh`, output in `results/gap-inprocess.txt`,
trace in `results/inprocess-trace.jsonl`.

**The workload** (`workloads/inproc_gap.py`) runs in **one** Python process and
starts **no** new program. It:

1. builds a directory tree in `scratch/inprocess/`, then removes it with
   `shutil.rmtree`, and removes a second file with `os.unlink`;
2. starts a listener on `127.0.0.1` on a port the kernel chooses, opens a TCP
   connection to it, and reads a payload;
3. writes a marker JSON that records what happened, including
   `new_programs_started`.

**The command.** The monitor is set to refuse everything it sees, so anything
it noticed would have been stopped:

```
agent-firewall run --approve deny --trace results/inprocess-trace.jsonl -- \
    python3 workloads/inproc_gap.py scratch/inprocess results/inprocess-marker.json
```

**What happened.** The firewall exited with status 0 and printed nothing to
standard error. The marker file says:

```json
{
  "files_removed": 6,
  "tree_exists_after": false,
  "single_file_exists_after": false,
  "tcp_port": 34891,
  "tcp_bytes_received": "payload-from-inside-one-process",
  "new_programs_started": 0
}
```

The directory tree is gone. The file is gone. The connection carried its
payload. The firewall was set to **deny**, and it denied nothing, because it
saw nothing to deny.

**What the trace holds.** Six events, in full:

| # | Type | What it says |
| --- | --- | --- |
| 1 | `session_start` | the command line and the capability report |
| 2 | `process_exec` | `python3` started |
| 3 | `process_fork` | a thread, `is_thread: true` |
| 4 | `process_exit` | that thread ended |
| 5 | `process_exit` | `python3` ended, code 0 |
| 6 | `session_end` | exit code 0, `process_count: 1` |

The search for the actions, over every line except `session_start`:

```
unlink   0     rmtree   0     remove   0     delete   0
connect  0     socket   0     tcp      0
tree-to-remove 0            single-file-to-unlink 0
```

**Zero.** The marker exists; the trace has no matching entry. That is the
objective proof of the gap.

**The contrast, same workload, other monitors.** Under
`ptrace_full --mode syscall`: 2 894 stops, 1 448 system calls, and the calls
that matter are all there — `unlink` 1, `unlinkat` 8, `rmdir` 1, `connect` 1,
`socket` 2, `openat` 135, `execve` **0**. Under `LD_PRELOAD`: 2 lines, one
`unlink` and one `connect` — better than nothing, and still 1 of 10 removals,
because of gap 4.

The `execve` count of 0 is the whole story in one number. The exec-only
monitor is not broken and it is not badly written; **the workload crossed the
boundary it watches exactly zero times.** The firewall's own capability report
in `session_start` already states this honestly:

> `file_open_events`, available **false**: "this version stops only at exec; a
> file open needs a stop at every system call (`PTRACE_SYSCALL`) or a kernel
> facility such as fanotify or eBPF"

**What it means for the product.** `docs/PRODUCT.md` §5 says the product dies
if it asks too many questions, and `docs/RESEARCH.md` §5 states this limit.
This spike turns the statement into a number and puts a shape on it.

* The gap is not about rare programs. It is about **long-lived interpreters**:
  `python3`, `node`, `ruby`, a language server, a REPL, a test runner, an
  agent's own process. A coding agent works inside these all day.
* Once a script starts, everything it does is invisible. `rm -rf` typed at a
  shell is caught. The same removal written as three lines of Python inside a
  script that already runs is not. **The protection depends on the shape of
  the command, not on how destructive it is** — and the shape is not something
  a user can reason about.
* No number of policy rules can close this. The rules are matched at an event
  that never fires. Better rules make the caught path better; they do not make
  the uncaught path smaller.
* The right honesty for the documentation is a sentence of this form: *"The
  firewall stops a destructive command when that command starts a new program.
  It does not see actions inside a program that already runs."* This spike is
  the evidence for that sentence.

## Can the target see the monitor

From `results/visibility.txt`. `selfcheck` reads `/proc/self/status`, its own
environment and `/proc/self/maps` under each monitor.

| Condition | `TracerPid` | `Seccomp` | `Seccomp_filters` | `NoNewPrivs` | `LD_PRELOAD` in the environment | Injected library in the maps |
| --- | --- | --- | --- | --- | --- | --- |
| no monitor | 0 | 0 | 0 | 0 | unset | none |
| exec-only `ptrace` (shipping) | **1866073** | 0 | 0 | 0 | unset | none |
| full `PTRACE_SYSCALL` | **1866077** | 0 | 0 | 0 | unset | none |
| `LD_PRELOAD` | 0 | 0 | 0 | 0 | **the library path** | **4 lines for `libafwpreload.so`** |
| a self-installed seccomp filter | 0 | **2** | **1** | **1** | unset | none |

Every mechanism here is visible to its own target, and the cost of looking is
close to zero. Two lines of shell find the tracer:

```sh
while read -r line; do case "$line" in TracerPid*) echo "$line";; esac
done < /proc/self/status
# under the shipping monitor:  TracerPid: 1866088
# with no monitor:             TracerPid: 0
```

The `Seccomp` row was produced by having `selfcheck` install an allow-all
filter on itself with `PR_SET_NO_NEW_PRIVS` and `SECCOMP_SET_MODE_FILTER`,
which needs no root. It shows that a seccomp monitor is equally visible: the
count of filters is in the same file. This is useful for the sibling threads:
no cheap unprivileged mechanism on Linux is hidden from its own target.

**Is this a real risk or a theoretical one?**

It is **real today, for an innocent reason, and not a security risk.**

* Real and innocent: reading `TracerPid` is a normal thing for ordinary
  software to do. Debuggers, crash handlers, test frameworks and language
  runtimes check it and change behaviour — they turn off a timeout, choose a
  different signal handling path, print more, or disable colour. A monitor
  that changes the behaviour of the subject weakens the premise of behaviour
  monitoring. The measured effect in this spike is small but not zero: under
  every `ptrace` monitor the target *is* a different process, with a different
  signal delivery path and different timing.
* Not a security risk in the threat model: `docs/PRODUCT.md` describes a tool
  that protects a user from the mistakes of an agent that is trying to be
  useful, not from an agent that is trying to escape. Against a hostile target
  none of these four mechanisms holds anyway — `LD_PRELOAD` falls to one
  `unset`, and a tracee can behave differently when `TracerPid` is nonzero.
  Full `PTRACE_SYSCALL` and seccomp cannot be turned off from inside, but they
  can be detected, and detection is enough for a hostile program to choose a
  path the monitor does not watch.
* The product consequence: **do not claim that the firewall is invisible, and
  do not build any feature that depends on it being invisible.** It should be
  visible on purpose and documented, in the same way a debugger is. The one
  thing to avoid is a design that assumes the agent behaves identically under
  supervision.

## Recommendation

**Keep exec-only `ptrace`.** It is the only cheap mechanism that both blocks
and never misses what it watches. It saw 301 of 301 processes with no race,
across `fork`, `clone` and `execve`, on every repeat. Its blocking works. And
the mechanism costs **0.042 ms for each new process** — the cheapest thing in
this study that can carry a decision at all.

**Drop `/proc` polling.** 99.7 % missed at every period, a quarter of a core
at the fastest period, and no way to block. It should not be a fallback and it
should not be a second source. A security tool that reports a subset of
processes chosen by a race is worse than one that says clearly what it does
not watch.

**Drop `LD_PRELOAD` as a control.** It has four measured gaps, three of which
an ordinary tool chain triggers without trying: a static Go binary such as
`gh`, a build system that cleans the environment, and any file operation whose
system call is not in the wrapper list. Its only advantage over the exec stop
is in-process visibility, and it delivers that badly: 1 of 10 removals in the
in-process test. If a future version wants argument-level detail cheaply, it
should be labelled a hint, never a control.

**Where the numbers say to invest, in order:**

1. **The 42.7 ms fixed session cost of the shipping monitor.** It is 41 % of
   the W1 overhead and it is the whole reason W2 shows 3.86×. It is paid once
   for each session, before any work, and the raw mechanism pays 0.2 ms. That
   is the cheapest win on the list, and it costs no coverage.
2. **The gap between 0.042 ms and 0.204 ms for each new process.** About four
   fifths of the marginal cost is the firewall's own work, not `ptrace`. A
   profile of the exec path — policy evaluation, the `/proc` reads for argv
   and cwd, input capture — should recover most of the 1.7× on W1 without
   changing what the monitor sees. **The exec boundary is not the expensive
   part of the shipping monitor.** That answers the open question in
   `docs/PRODUCT.md` §6 for the cost half.
3. **The in-process gap needs a system call path, not more rules.** This is
   the real coverage question, and the price is now known:
   full `PTRACE_SYSCALL` gives complete visibility for an unprivileged target,
   except vDSO calls and shared-mapping writes, at 2.28×/5.43×/2.42× and about
   5 µs for each stop. That is too much to leave on for a whole session, but
   the unit cost is the useful part: **the cost is proportional to the system
   call count**, so a design that stops only at a chosen set of calls pays only
   for those calls. That is exactly the shape of seccomp user notification,
   which a sibling thread measures. If its per-call cost is near this 5 µs and
   its filter can select a small set of calls, it closes this gap at a cost the
   product can pay. **This spike does not recommend shipping full
   `PTRACE_SYSCALL`; it recommends using these numbers as the bar that the
   seccomp result must beat.**
4. **Document the limit in the user's words.** The in-process demonstration is
   reproducible in one command. It belongs in `docs/DETECTION-RESEARCH.md` as
   the concrete example behind the sentence about what the firewall does not
   see. A user who knows the boundary can work with it. A user who is told
   "we see everything" will trust it in exactly the case where it is wrong.
