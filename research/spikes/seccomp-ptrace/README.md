# Spike: seccomp with ptrace (`SECCOMP_RET_TRACE`)

This is a research spike. It is not product code. It answers one question:

> Can a `seccomp` BPF filter give `af-monitor` system-call visibility at a
> price that the product can pay, and keep everything that `af-monitor`
> already does?

The answer and all numbers are in [FINDINGS.md](FINDINGS.md).

The spike is C on purpose. It stays outside the Cargo workspace of the
product, so `cargo build --workspace` in the repository root does not see it.

## Run everything with one command

```sh
make check
```

`make check` builds the three binaries, runs the test suite (61 checks), and
then runs the benchmark. The benchmark takes several minutes.

## Run the parts on their own

```sh
make                       # build only
make test                  # the test suite, about 40 seconds
./tests/run-tests.sh block # run only the tests whose name holds "block"
make bench                 # the cost curve, several minutes
./bench/run-bench.sh --runs 15 --configs "a b c d" --with-strace
./bench/count-stops.sh     # exact number of supervisor stops per workload
./bench/write-cost.sh      # the price of tracing write
make clean
```

The benchmark calls the shared harness `research/bench/bench.sh`. Do not set
`TMPDIR`: the harness makes its work directory with `mktemp -d`, and a
different file system changes the file workload by a factor of two.

## The binaries

| Binary | What it does |
| --- | --- |
| `build/afw-hybrid` | The supervisor. It starts a program, installs a `seccomp` filter, and traces the calls that the filter selects. |
| `build/nnp-probe` | Tests `PR_SET_NO_NEW_PRIVS`. `--check` says whether the filter needs it. |
| `build/victim` | A small target program for the tests. It opens files in a loop, and it can run a two-thread race. |

## How the supervisor works

1. The supervisor forks. The child calls `PTRACE_TRACEME`. The child does
   **not** raise `SIGSTOP`; see `docs/RESEARCH.md` section 3 for the deadlock
   that `SIGSTOP` causes.
2. The child installs the `seccomp` filter and calls `execve` on the target.
   The filter returns `SECCOMP_RET_TRACE` with a small group number for the
   interesting calls and `SECCOMP_RET_ALLOW` for all the others.
3. The supervisor sets `PTRACE_O_TRACESECCOMP` next to the options that
   `af-monitor` already sets (`TRACEFORK`, `TRACEVFORK`, `TRACECLONE`,
   `TRACEEXEC`, `TRACEEXIT`, `EXITKILL`).
4. At `PTRACE_EVENT_SECCOMP` the supervisor reads the group number with
   `PTRACE_GETEVENTMSG`, reads the arguments with `PTRACE_GET_SYSCALL_INFO`,
   and reads pointer arguments through `/proc/<pid>/mem`.

### Why there is a stage two

`SECCOMP_RET_TRACE` returns `-ENOSYS` and skips the call when no tracer has
`PTRACE_O_TRACESECCOMP`. The supervisor can only set that option at a
ptrace-stop, and the first stop is the `SIGTRAP` **after** the first `execve`.
A filter that traces `execve` therefore breaks its own `execve`.

The spike solves this in two ways:

* Default: the child execs `/proc/self/exe --stage2 ...`. The supervisor sets
  the options at that stop. Stage two then installs the filter and execs the
  real target.
* `--direct`: the child installs the filter and execs the target at once.
  This works only for a filter that does not trace `execve` (configs `f`, `g`,
  `w`, `x`, `e`). **This is the shape that the product should use**, because
  `af-monitor` already gets exec from `PTRACE_EVENT_EXEC` and does not need
  `execve` in the filter.

## The filter configurations

| Config | What the filter traces |
| --- | --- |
| `x` | Nothing. No filter at all. This is `af-monitor` of today. |
| `z` | A filter is installed, but every rule says `ALLOW`. It measures the price of the filter itself. |
| `a` | `execve`, `execveat` |
| `b` | `a` plus `openat` when the `flags` argument asks for a change |
| `c` | `a` plus every `openat` and `open` |
| `d` | `c` plus `unlinkat`, `unlink`, `renameat2`, `rename`, `connect`, `openat2` |
| `f` | `d` without `execve`. The product filter. Use it with `--direct`. |
| `g` | `f`, but only the opens that ask for a change |
| `w` | `write`, `writev`, `sendto`, `sendmsg`, `connect`. The price of seeing content. |
| `e` | No filter. `PTRACE_SYSCALL` stops on every call. The slow reference. |

## Useful options of `afw-hybrid`

```
--config <letter>     which filter (default d)
--direct              install the filter without stage two
--quiet               print no event lines
--stats               print the counters at the end
--log <path>          write the event lines to a file
--no-nnp              do not set PR_SET_NO_NEW_PRIVS
--no-paths            do not read pointer arguments
--block <call>        refuse the call with EPERM
--block-path <text>   refuse only when the path holds this text
--die-after <n>       leave the supervisor at seccomp stop n (tests EXITKILL)
--detach-after <n>    detach at stop n
--reattach-ms <n>     how long the supervisor stays away
```

## Safety

The tests never touch a real database and never open a connection to a real
remote host. The only address in use is `127.0.0.1` on port 9, and nothing
answers there. Every file that the tests write goes into `work/`, which
`.gitignore` holds.
