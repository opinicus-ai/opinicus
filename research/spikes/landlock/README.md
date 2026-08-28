# Spike: Linux Landlock

Research for the Agent Firewall. It answers one question:

> Which dangerous actions can we make **impossible**, so that nobody has to be
> asked at all?

Every other detection thread in `research/spikes/` answers "how do I ask the
user well?". `docs/PRODUCT.md` section 5 says the product dies of too many
questions, so a rule that never interrupts is worth more than a rule that
interrupts well.

The result is in **[`FINDINGS.md`](FINDINGS.md)**.

## Run everything

```sh
make run-all
```

That builds the programs, runs the 65 test assertions, counts the rule pack,
and runs the shared benchmark. It takes about six minutes, most of it the
benchmark.

Smaller steps:

```sh
make            # build into bin/
make probe      # print the Landlock ABI of this kernel
make check      # the 65 test assertions
make rules      # how much of policies/*.yaml could move to Landlock
make bench      # the shared harness in six configurations
make clean
```

## Safety rules that this spike keeps

`landlock_restrict_self()` **cannot be undone**. A process that restricts
itself is restricted until it dies.

1. **No program here ever restricts the shell that starts it.** The launcher
   `bin/afw-landlock` forks, and only the child gets the ruleset. `bin/probe-abi`
   never calls `landlock_restrict_self` at all.
2. **Every command in every test is wrapped in `timeout`.** A sandbox makes
   operations fail, so a workload under a sandbox can stop. A test that hangs
   is worse than a test that fails.
3. **The benchmark always runs with `--timeout 20`.**
4. **Nothing real is written.** The credential tests use a fake home under
   `work/`. The one test that touches the real `~/.ssh` only tries to *read*
   it, inside a sandbox, and asserts that the read fails.
5. This spike is **not** in the Cargo workspace. It is C with a `Makefile`, so
   it cannot take the cargo file lock.

## The launcher

```
afw-landlock [options] -- COMMAND [ARG...]

  --ro PATH            read and list under PATH
  --rx PATH            read, list and execute under PATH
  --rw PATH            read, write, create, delete and execute under PATH
  --rw-noexec PATH     the same, but no program may start from PATH
  --hide PATH          carve PATH out of every grant above it
  --handle-net         handle the TCP rights; with no --connect-tcp every
                       connect is denied
  --connect-tcp PORT   allow connect() to this TCP port
  --bind-tcp PORT      allow bind() to this TCP port
  --scope-signal       deny a signal to a process outside the sandbox
  --no-sandbox         fork and exec with no ruleset, for the benchmark
  --stats              print the rule count and the build time to stderr
  --verbose            print every rule to stderr
```

Example, the product shape:

```sh
./bin/afw-landlock \
    --rx /usr --rx /etc \
    --rw   "$PWD"                 \
    --rw-noexec /tmp              \
    --ro   "$HOME/.config"        \
    --hide "$HOME/.ssh"           \
    --hide "$HOME/.aws/credentials" \
    --scope-signal                \
    -- bash
```

`--hide` needs a word of explanation. Landlock is an allow list and it has
**no deny rule**: a right that a rule gives on a directory reaches every file
under it, and a rule deeper in the tree can only add rights
(`bin/rule-specificity` proves this). So `--hide` walks from the granted
directory down to the hidden one and grants each entry on the way, but never
the hidden path. The price is that the directory holding a hidden path cannot
be listed. See `## The limits` in `FINDINGS.md`.

## Files

| Path | What it is |
| --- | --- |
| `src/landlock_common.h` | the three system calls, the right tables, the ABI detection |
| `src/probe_abi.c` | what this kernel supports. Only asks; never restricts |
| `src/afw_landlock.c` | the sandbox launcher |
| `src/fs_probe.c` | the target. Runs an operation and prints its error number |
| `src/escape_test.c` | six attempts to get out of the sandbox |
| `src/rule_specificity.c` | can a deeper rule take a right away? |
| `src/tcp_listener.c` | a listener with its own `alarm()` for the network tests |
| `tests/run-tests.sh` | 65 assertions |
| `tests/count-rules.py` | the rule pack against what Landlock can carry |
| `bench/run-bench.sh` | the shared harness in six configurations |
