# Baselines spike: the cost and the coverage of the cheap mechanisms

This spike measures four ways to watch the child processes of a coding agent
on Linux, with no root and no kernel module:

| Mechanism | Tool in this spike |
| --- | --- |
| `/proc` polling | `src/procpoll.c` |
| `LD_PRELOAD` interposition | `src/preload.c` |
| Exec-only `ptrace` | `target/release/agent-firewall`, the shipping monitor |
| Full `PTRACE_SYSCALL` | `src/ptrace_full.c` |

For each mechanism it measures **what it costs** and **what it misses**. The
answers are in `FINDINGS.md`. The raw output of every run is in `results/`.

---

## Run everything with one command

```sh
cd research/spikes/baselines
./run-all.sh          # 7 runs for each benchmark, about four minutes
./run-all.sh 15       # 15 runs, a quieter number
```

`run-all.sh` builds the tools, builds the shipping monitor when it is
missing, and then writes every file in `results/`.

## Build only

```sh
make            # the C tools, the C workloads and the static Go workload
make clean
```

The build needs `gcc`. It uses `go` when `go` is present, and it says so when
`go` is missing. It never joins the Cargo workspace.

---

## Run one measurement

| Command | What it answers |
| --- | --- |
| `./scripts/bench-all.sh 15` | the median milliseconds of W1, W2 and W3 for every mechanism |
| `./scripts/startup-cost.sh` | the fixed cost of one session, with `/bin/true` as the target |
| `./scripts/per-exec.sh` | splits the cost into a fixed part and a part for each new process |
| `./scripts/cpu-cost.sh 3` | the processor share that the poller uses |
| `./scripts/syscall-rate.sh` | the cost of one `ptrace` system call stop |
| `./scripts/gap-polling.sh 5` | how many processes the poller never sees |
| `./scripts/gap-preload.sh` | the structural gaps of `LD_PRELOAD` |
| `./scripts/gap-inprocess.sh` | **the in-process gap of the shipping monitor** |
| `./scripts/gap-syscall.sh` | whether full `PTRACE_SYSCALL` has a gap |
| `./scripts/blocking.sh` | whether each mechanism can stop an action |
| `./scripts/visibility.sh` | what the target can learn about its monitor |

Every script writes a text file with the same name in `results/`.

---

## Safety

Every test is safe to run again on a developer machine.

* The action of every coverage test is a **marker file** inside `scratch/`.
  Nothing destructive is needed to prove that a monitor saw nothing.
* The network test uses a listener that the test starts itself on
  `127.0.0.1`, on a port that the kernel chooses. No remote host is used.
* `scripts/blocking.sh` uses `policies/spike-blocking.yaml`. That rule matches
  only the marker program of this spike, so the blocking test cannot stop a
  real command.
* Nothing runs as root. Nothing writes outside this directory, except the
  temporary directory that the shared harness `research/bench/bench.sh` makes
  for itself.

---

## What is where

```
Makefile                  builds every tool and workload into bin/
run-all.sh                builds, then runs every measurement
src/procpoll.c            the /proc polling supervisor
src/preload.c             the LD_PRELOAD interposer, with a deny mode
src/ptrace_full.c         the PTRACE_SYSCALL tracer, with a deny mode
src/selfcheck.c           prints what a target knows about its monitor
workloads/                the programs that perform the measured actions
wrappers/preload-wrap.sh  runs a command under the interposer
scripts/                  one script for each measurement
policies/                 the rule for the blocking test
results/                  the output of the last run
scratch/                  working files; every test makes its own again
```

## The tools

**`bin/procpoll`** runs a command and reads `/proc/<pid>/stat` for every
process at a fixed period. It rebuilds the tree from `ppid` and records every
descendant. It reports the number of processes that it saw, the number of
polls, its own processor time and the wall-clock time.

```sh
bin/procpoll --period-ms 10 --log seen.txt --summary sum.txt -- /bin/sh work.sh
```

**`bin/ptrace_full`** has two modes. `--mode syscall` stops the target at
every system call and counts the calls by number. `--mode events` stops it
only at fork, clone, exec and exit, which is the shape of the shipping
monitor; this spike uses that mode to make a race-free ground truth. `--deny`
makes the tracer refuse named calls, which shows that the mechanism can
block.

```sh
bin/ptrace_full --mode syscall --histogram h.txt -- python3 script.py
bin/ptrace_full --mode syscall --deny openat -- ./bin/marker_libc out.txt
```

**`bin/libafwpreload.so`** wraps `execve`, `openat`, `unlink` and `connect`.
`AFW_PRELOAD_LOG` names the log file. `AFW_PRELOAD_DENY` names a text; a path
that holds that text is refused with `EACCES`.

**`bin/selfcheck`** prints `TracerPid`, `Seccomp`, `Seccomp_filters` and
`NoNewPrivs` from `/proc/self/status`, its own `LD_PRELOAD` variable and any
injected library in `/proc/self/maps`. With `--install-seccomp` it first puts
an allow-all filter on itself, which needs no root.

## The workloads

| File | What it does |
| --- | --- |
| `workloads/marker_libc.c` | writes a marker with the libc `openat`, removes a file with `unlink`, connects with `connect` |
| `workloads/marker_rawsyscall.c` | the same, but with `syscall(SYS_openat, ...)`, so it never uses the libc symbol |
| `workloads/marker_static.c` | the same, but with no library at all, so the dynamic linker never runs |
| `workloads/gomarker/main.go` | a static Go program, the normal shape of `gh`, `kubectl` and `terraform` |
| `workloads/vdso_and_mmap.c` | calls `clock_gettime` many times and changes a file through a shared mapping |
| `workloads/inproc_gap.py` | removes a tree, removes a file and opens a TCP connection, all in one process and with no new program |
| `workloads/one_shot_listener.py` | a local listener that accepts one connection |
