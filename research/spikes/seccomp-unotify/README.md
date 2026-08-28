# Spike: `seccomp` user notification

This spike answers one question for the Agent Firewall: can
`SECCOMP_USER_NOTIF` stop a destructive action **inside** a program that
already runs? `docs/PRODUCT.md` section 6 names that gap. `docs/RESEARCH.md`
sections 5 and 7 leave it open.

The answer is in **[FINDINGS.md](FINDINGS.md)**. Read that first.

This directory holds only C and shell. It is **not** part of the Cargo
workspace, and `cargo build --workspace` does not see it.

---

## Run everything with one command

```sh
make run-all
```

That command builds every program, runs the whole test set, and then runs the
shared benchmark harness. It needs about four minutes. It needs no root, no
network and no database.

Smaller steps:

| Command | What it does |
| --- | --- |
| `make` | builds every program into `bin/` |
| `make check` | runs the test set (31 tests, about two minutes) |
| `make bench` | runs `research/bench/bench.sh` in six configurations |
| `make clean` | removes `bin/` and `work/` |

Every test writes its files under `work/`. Nothing leaves this directory.

---

## The programs

| Program | What it is for |
| --- | --- |
| `bin/afw-unotify` | the supervisor: it starts a target under a filter and answers each notification |
| `bin/probe-listener` | prints what this kernel gives to an unprivileged user |
| `bin/toctou-open` | two threads share one path buffer; measures how often the read path is wrong |
| `bin/toctou-execve` | the same race on the program start boundary |
| `bin/slow-target` | opens files one by one; used by the failure tests |
| `bin/show-creds` | prints the identity and the `no_new_privs` state |

## The supervisor

```
afw-unotify [options] -- COMMAND [ARGS...]

  --filter=exec|full|io     which system calls to trap (default full)
  --allow=continue|emulate  how an allowed call proceeds
  --deny=TEXT               refuse a path or an address that holds TEXT
  --deny-call=NAME          refuse a whole system call
  --log=FILE                one line for each notification ("-" is stderr)
  --trigger=TEXT            delay, hold and exit apply only to a match
  --delay-ms=N              wait N ms before each answer
  --exit-after=N            the supervisor exits after N answers
  --no-answer               receive but never answer
  --suicide-ms=N            the supervisor dies after N ms
  --trap-sendmsg            add sendmsg; this deadlocks on purpose
  --no-read-args            do not read the memory of the target
  --killable-recv           add WAIT_KILLABLE_RECV to the filter
  --stats                   print counters at the end
```

Examples:

```sh
# See what a command really touches.
./bin/afw-unotify --log=- -- git status

# Refuse every open of a path that holds "secret".
./bin/afw-unotify --deny=secret -- cat /etc/passwd

# Measure the argument race yourself.
mkdir -p work/demo && echo A > work/demo/f_a.txt && echo B > work/demo/f_b.txt
./bin/afw-unotify --log=work/demo/log -- \
    ./bin/toctou-open --dir=work/demo --out=work/demo/out --iters=2000
python3 tests/compare-toctou.py work/demo/log work/demo/out
```

## How the supervisor gets the listener

1. The supervisor makes a `socketpair` and forks.
2. The child calls `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
3. The child installs a classic BPF filter with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER` and receives a listener descriptor.
4. The child sends that descriptor to the supervisor in an `SCM_RIGHTS`
   message, and then calls `execve`.
5. The supervisor loops on `SECCOMP_IOCTL_NOTIF_RECV`, reads the pointer
   arguments through `/proc/<pid>/mem`, and answers with
   `SECCOMP_IOCTL_NOTIF_SEND` or `SECCOMP_IOCTL_NOTIF_ADDFD`.

Step 4 has a trap. The filter already works at step 3. If the filter traps
`sendmsg`, then step 4 waits for a supervisor that does not have the listener
yet, and the pair hangs for ever. `--trap-sendmsg` shows that hang, and the
test set proves it.
