# Spike: `seccomp` user notification (`SECCOMP_USER_NOTIF`)

Date: this run. Machine: Fedora 43, kernel `7.0.9-105.fc43.x86_64`, x86_64,
8 CPUs, uid 1000, no root, no `sudo`, `kernel.unprivileged_bpf_disabled = 2`.

Everything below comes from a program in this directory that I ran. Each
number can be produced again with `make run-all`.

---

## Verdict

**Yes, with conditions, and the conditions are narrow.** `SECCOMP_USER_NOTIF`
works for an unprivileged user on this machine. It is cheap (1.1× to 1.5× on
the shared benchmark, 7 to 21 microseconds for each trapped call). It refuses
an action reliably: no refused call ever ran, in any test. One listener covers
a whole process tree, and it also covers a child that never calls `execve`. So
it does close a real part of the gap that `docs/PRODUCT.md` section 6 names.
But the supervisor reads the path from the memory of the target, and the
kernel reads that memory again after the answer. When a second thread writes
the same buffer, **the path that the supervisor read was not the path that the
kernel opened in 47.6% of 10000 opens**, and a rule "refuse this file" failed
to hold 12% to 29% of the time. `docs/PRODUCT.md` section 3 asks for a
deterministic decision, and a decision from a raced pointer is not
deterministic. The supervisor can remove the race for a file open: it opens
the file itself and injects the descriptor with `SECCOMP_IOCTL_NOTIF_ADDFD`,
and that measured **0 wrong decisions in 6000 opens with the writer thread
still running**. It cannot do this for `execve`, because no process can start
a program for another process. So `af-monitor` must keep `ptrace` for the
program start boundary, and it can add user notification for file and network
calls, with emulation, behind a switch that the user turns on.

---

## What I ran

| File | What it does |
| --- | --- |
| `src/afw_unotify.c` | the supervisor. It forks, the child sets `no_new_privs`, installs a BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, sends the listener over a `socketpair` with `SCM_RIGHTS`, and calls `execve`. The parent loops on `SECCOMP_IOCTL_NOTIF_RECV`, reads the arguments through `/proc/<pid>/mem`, and answers with `SECCOMP_IOCTL_NOTIF_SEND` or `SECCOMP_IOCTL_NOTIF_ADDFD`. |
| `src/probe_listener.c` | records what the kernel gives to uid 1000. |
| `src/toctou_open.c` | two threads share one path buffer. Thread A calls `openat` on it in a loop. Thread B writes a different valid path into it in a loop. The truth comes from `readlink("/proc/self/fd/N")`. |
| `src/toctou_execve.c` | the same race for `execve`. The path is in a shared mapping. `p_a` is a copy of `/bin/true`, `p_b` is a copy of `/bin/false`, so the exit status names the program that really ran. |
| `src/slow_target.c` | opens files one by one and prints the time of each open. It drives the failure tests. |
| `src/show_creds.c` | prints uid, euid, `PR_GET_NO_NEW_PRIVS` and `CapEff`. |
| `tests/compare-toctou.py` | joins the log of the supervisor and the result of the target on a sequence number, and prints the mismatch rate. |
| `tests/run-tests.sh` | 31 assertions. `make check`. All pass. |
| `bench/run-bench.sh` | calls the shared harness `research/bench/bench.sh` in six configurations. |

The filter traps `openat`, `openat2`, `unlinkat`, `renameat2`, `rename`,
`renameat`, `unlink`, `connect`, `execve` and `execveat`. The `io` preset adds
`write`, `writev` and `sendto`.

What this kernel gives to uid 1000, from `bin/probe-listener`:

```
actions_avail                  = kill_process kill_thread trap errno user_notif trace log allow
new_listener_unprivileged      = yes (fd=3)
wait_killable_recv             = yes
second_listener_in_same_process= Device or resource busy (EBUSY)
notif_sizes                    = notif:80 resp:24 data:64
```

---

## Measured results

`./research/bench/bench.sh --runs 7`, median wall clock in ms. The first three
rows are the numbers that the task gave me. The `none` row of my own session
is 150 / 27 / 87, so I give my ratios against my own baseline.

| Wrapper | W1 exec | W2 file | W3 mixed |
| --- | --- | --- | --- |
| none (task baseline) | 145 ms | 13 ms | 83 ms |
| `strace -f -qq` | 426 ms (2.9×) | 108 ms (8.3×) | 248 ms (3.0×) |
| `strace -f -qq --seccomp-bpf -e trace=execve` | 216 ms (1.5×) | 16 ms (1.2×) | 112 ms (1.3×) |
| none (my session baseline) | 150 ms | 27 ms | 87 ms |
| **unotify, `execve` only** | **169 ms (1.13×)** | **26 ms (0.96×)** | **94 ms (1.08×)** |
| **unotify, full set** | **181 ms (1.21×)** | **40 ms (1.48×)** | **118 ms (1.36×)** |
| unotify, full set, no memory read | 166 ms (1.11×) | 37 ms (1.37×) | 105 ms (1.21×) |
| unotify, full set, every open emulated | 177 ms (1.18×) | 40 ms (1.48×) | 109 ms (1.25×) |
| unotify, full set plus `write`/`writev`/`sendto` | 177 ms (1.18×) | 41 ms (1.52×) | 107 ms (1.23×) |

The filter selection is the main cost. For W2, which is a file workload, the
exec-only filter costs nothing (0.96×) and the full set costs 1.48×.

Cost for each notification, from 20000 opens in a loop:

| Work in the supervisor | Time for each trapped call |
| --- | --- |
| answer only, no memory read | 7 µs |
| answer, and read the path from `/proc/<pid>/mem` | 16 µs |
| open the file, and inject the descriptor with `ADDFD` | 21 µs |

Number of notifications for a workload of 50 `execve` calls and one `cat`:
52 with the exec filter, 171 with the full set, 172 with the content set.

The content set looks cheap in the table above, because the benchmark
workloads write little. A write workload shows the true price. `dd
if=/dev/zero of=/dev/null bs=512 count=50000` makes 50000 writes:

| Wrapper | Time |
| --- | --- |
| no monitor | 52 ms |
| full set (`write` is not trapped) | 55 ms (1.1×) |
| content set (`write` is trapped) | **422 ms (8.1×)** |

To watch the *name* of an object is cheap. To watch the *data* of an action
costs as much as full `ptrace`.

---

## Can it refuse an action

**Yes. A refusal always holds.**

| Test | Result |
| --- | --- |
| refuse `openat` of `secret.txt` | the target printed "Operation not permitted", and the file still held `ORIGINAL` |
| refuse `unlinkat` | `rm` exited 1, and the file is still on disk |
| refuse `connect` to `127.0.0.1:9` | the target got `EPERM`, not `ECONNREFUSED` |
| 936 refused opens in the race test | **0** of them ran |

The last row is the important one. The supervisor can pick the wrong file (see
the next section), but when it says no, the call does not happen. The refusal
mechanism is sound. Only the *decision* is not.

An error number goes back to the target as an ordinary system call error. The
target sees `EPERM`. It cannot tell a firewall from a permission problem.

---

## Argument read reliability

**This is the central result. The read is exact when nothing changes the
buffer, and it is a coin flip when a second thread writes the buffer.**

`toctou_open.c` has two threads and one shared path buffer. Thread A calls
`openat` on that buffer. Thread B writes `f_a.txt` or `f_b.txt` into the same
buffer. Both files are ordinary files in `work/`. Each open carries a sequence
number in the `mode` argument, which `openat` ignores without `O_CREAT`. The
truth comes from `readlink("/proc/self/fd/N")` after the open.

| Configuration | Opens | Wrong reads | Rate |
| --- | --- | --- | --- |
| one thread, no writer | 2000 | 0 | **0.0%** |
| two threads, answer with `CONTINUE` | 10000 (5 runs) | 4761 | **47.6%** (45.3% to 52.2% for each run) |
| two threads, supervisor opens the file and injects it with `ADDFD` | 6000 (3 runs) | 0 | **0.0%** |

The same test with a policy shows what this does to a rule. The rule was
"refuse every open of `f_b.txt`":

| Run | Refusals | `f_b.txt` was opened anyway | Refused calls that ran |
| --- | --- | --- | --- |
| run 1 | 993 of 2000 | 250 of 2000 (12.5%) | 0 |
| run 2 | 936 of 2000 | 518 of 2000 (25.9%) | 0 |
| run 3 | 650 of 2000 | 581 of 2000 (29.1%) | 0 |

The same happens for a program start. `toctou_execve.c` forks 400 times with
the rule "refuse `p_b`". The supervisor allowed 272 `execve` calls after it
read `p_a`, and the kernel then ran the refused program `p_b` **105 times of
400**.

**What this means for the product.** A rule that names a path is not a
guarantee. It is a filter with a hole, and the size of the hole depends on the
target, not on the firewall. `docs/PRODUCT.md` section 3 says a decision must
be deterministic and must not depend on a race. A `CONTINUE` answer breaks
that rule.

Three more points make this worse than the rate alone:

1. **The supervisor cannot tell the two cases apart.** Nothing in the
   notification says whether the buffer is stable. The 0.0% case and the 47.6%
   case look the same from inside the supervisor.
2. **The fault is silent.** No error, no log line, no counter. The supervisor
   reports the wrong path with full confidence.
3. **The wrong read cuts both ways.** It can let a bad action through, and it
   can also refuse a harmless one. A false refusal is a false question to the
   user, and `docs/PRODUCT.md` section 5 says that this is what kills the
   product.

**The fix that works, and its limit.** For `openat` the supervisor does not
have to trust the read. It opens the path itself, and it gives the descriptor
to the target with `SECCOMP_IOCTL_NOTIF_ADDFD` and
`SECCOMP_ADDFD_FLAG_SEND`. The target then gets the exact file that the
supervisor examined. That measured 0 wrong decisions in 6000 opens with the
writer thread at full speed. The supervisor must then copy the semantics of
the call exactly: the `dirfd`, the flags, the mode, the `umask`, `O_CREAT`,
the symbolic links, and the working directory of the target. That is a large
amount of careful work for each call, and each mistake is a new bug in a
security tool.

Also, a small trap that costs an hour to find: `req.data.args[N]` holds the
raw register. `AT_FDCWD` arrives as `0x00000000ffffff9c`, and not as `-100`.
The value must be cast to the declared width of the parameter first.

---

## Descendant coverage

**One filter at the session root is enough. This part is good news.**

| Test | Result |
| --- | --- |
| `sh -c 'echo x \| sh -c "cat file"'` | one listener saw **5 different process ids** |
| a refusal for a grandchild, after two `execve` calls | it holds |
| a forked child that never calls `execve` | the filter covers it |
| the target installs its own listener | **EBUSY** |

The filter goes down through `fork` and through `execve`, and one listener
descriptor carries the notifications of the whole tree. The supervisor sees
the pid in `req.pid`, so it can tell the processes apart.

The `EBUSY` row is a limit to keep in mind. The kernel gives only one listener
for one filter chain. A program under the monitor that wants its own user
notification, for example a container tool or a sandbox, will fail. A plain
filter without a listener still works.

---

## The no_new_privs cost

`seccomp` for an unprivileged user needs `PR_SET_NO_NEW_PRIVS`. That flag
stops a setuid program from getting its privilege.

| Test | Without the monitor | Under the monitor |
| --- | --- | --- |
| `PR_GET_NO_NEW_PRIVS` in the target | 0 | **1** |
| the same in a forked child | 0 | **1** |
| `pkexec /bin/true` | it reached the authentication step | **"pkexec must be setuid root"** |
| `ping -c1 127.0.0.1` | it works | it works |
| `passwd -S` | it works | it works |
| `podman unshare id` | it works | it works |

The machine has 24 setuid programs. The list holds `sudo`, `su`, `mount`,
`umount`, `passwd`, `chsh`, `pkexec`, `crontab`, `gpasswd` and `fusermount3`.
Every one of them loses its privilege under the monitor.

**What this means for the product.** The cost is real but it is narrower than
it first looks. The tools that a coding agent uses in a normal session were
not affected in my tests. `ping` on this machine is **not** setuid; it uses
`ping_group_range`, which covers every group. Rootless `podman` worked.
`passwd -S` reads a file and does not need the privilege.

But `sudo` and `su` are in the list. An agent session that runs `sudo dnf
install` will fail under the monitor, and it will fail with a confusing
message from the tool, not from the firewall. `docs/PRODUCT.md` section 5 says
that a user who is annoyed switches the tool off. So:

- The firewall must **not** turn this on for every session by default.
- If it turns this on, it must detect the failure and print a clear message.
  "`sudo` cannot work while the firewall watches this session" is honest. "sudo
  must be setuid root" is not.
- `ptrace` has no such cost. It does not need `no_new_privs`, and a setuid
  program keeps its privilege under `ptrace`, although the kernel then drops
  the privilege for a different reason. This is a real advantage of the
  current design.

I did not measure a program with a file capability, such as `newuidmap`. State
this as untested.

---

## Failure modes

**No test froze the machine. A target under a stuck supervisor stays
killable.**

| Test | What I measured |
| --- | --- |
| supervisor waits 200 ms for each answer | each `open` in the target took exactly 200 to 201 ms; 5 opens took 1.002 s |
| supervisor never answers | the target blocks, and a signal still ends it (wrapper exit 142 = 128 + `SIGALRM`) |
| supervisor dies while the target waits | the waiting `open` returned **ENOSYS (38)** at once, after 800 ms |
| supervisor dies after one answer | every later trapped call returned **ENOSYS (38)** with no wait |
| a signal arrives during the wait | the notification is cancelled; `ID_VALID` goes stale and the answer fails with `ENOENT` |
| the same, and the handler has `SA_RESTART` | the kernel asks a **second time**: one `open` made **2 notifications** and took 3000 ms |
| the same, and the handler has no `SA_RESTART` | the call returns **EINTR (4)** |

Four points for the product:

1. **The target waits exactly as long as the supervisor thinks.** There is no
   timeout in the kernel. A supervisor that asks the user a question inside a
   notification stops the program for the whole time of the question.
2. **A death of the supervisor fails closed, but it breaks the program.**
   `ENOSYS` is not a normal error for `openat`. Most programs handle it badly.
   The user sees a strange failure and not a clean stop.
3. **A signal can double the question.** With `SA_RESTART` one `open` made two
   notifications. A firewall that asks the user would ask twice for one
   action. `docs/PRODUCT.md` section 5 calls this the thing that kills the
   product.
4. `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` is available on this kernel and
   makes the wait cleaner for a signal that does not kill.

### `SECCOMP_IOCTL_NOTIF_ID_VALID`

| It protects against | Evidence |
| --- | --- |
| a stale request, because the target died and the kernel reused the id | the sequence `id-valid-before ok=1` → the target dies → `stale-after-wait errno=2` → the answer fails with `ENOENT` |

| It does **not** protect against | Evidence |
| --- | --- |
| a changed argument | in the run with a 51.4% wrong-path rate, `ID_VALID` reported a problem **0 times** |

`ID_VALID` answers "does this request still exist?". It never answers "is the
memory that I read still the memory that the kernel will read?". Those are
different questions. A supervisor that checks `ID_VALID` and then answers
`CONTINUE` is not safe. It only knows that it talks to the right process.

---

## What it cannot do

1. **It cannot make a safe decision from a pointer argument with `CONTINUE`.**
   47.6% wrong in the worst realistic case. The manual says this, and I
   measured it.
2. **It cannot emulate `execve`.** No process can start a program for another
   process. So the program start boundary is always a `CONTINUE`, and the
   measurement shows 105 refused programs of 400 ran. `PTRACE_EVENT_EXEC` does
   not have this problem: it stops after the kernel loaded the image, so it
   judges the real program and not a pointer (`docs/RESEARCH.md` section 5).
3. **It cannot see a destructive action that makes no system call with a name
   in it.** A `DROP DATABASE` inside a library becomes a `write` or a `sendto`
   on a socket that is already open. To trap those costs 8.1× on a write
   workload, and the supervisor must then parse a protocol from a buffer that
   the same race can change. This spike does **not** close that part of the
   gap in `docs/PRODUCT.md` section 6.
4. **It cannot watch `sendmsg` with this design.** The filter works from the
   instant of the install, and the child passes the listener with `sendmsg`.
   So a trapped `sendmsg` waits for a supervisor that does not have the
   listener yet, and the pair hangs for ever. I reproduced this on purpose
   (`--trap-sendmsg`, exit 124 under `timeout`). A production monitor needs
   `pidfd_getfd`, or a rule in the BPF program that lets the setup call
   through.
5. **It cannot resolve a path for you.** The argument arrives raw: relative to
   the working directory of the target, with a `dirfd`, and with symbolic
   links. Resolution is the work of the supervisor, and resolution is racy in
   the same way.
6. **It cannot run two listeners in one process tree.** A target that installs
   its own listener gets `EBUSY`.
7. **A setuid program cannot get its privilege.** See the section above.
8. **My BPF program answers `ALLOW` for any architecture that is not
   `AUDIT_ARCH_X86_64`.** I could not test this, because this machine has no
   32-bit toolchain. A production filter must return an error for a foreign
   architecture, or a 32-bit program can pass around the rules.

One more trap that a production monitor must handle. A `/proc/<pid>/mem`
descriptor binds to the memory map at the time of the open. `execve` gives a
new map, so a cached descriptor reads nothing after it. The first `openat`
after every program start then gives an **empty path**, and a monitor that
cached the descriptor fails open, silently, at the exact moment when a new
program starts. I hit this bug and fixed it with a retry that opens the
descriptor again.

---

## Recommendation for the product

**Adopt it, but only in a narrow form, and do not replace `ptrace` with it.**

1. **Keep `ptrace` for the program start boundary.** `PTRACE_EVENT_EXEC`
   judges a loaded image. The `seccomp` `execve` trap judges a user pointer
   that the kernel reads again, and 105 refused programs of 400 ran in my
   test. The current design is stronger here, not weaker.
2. **Keep the user question in `ptrace`, and not in a notification.** A
   notification blocks the target for the whole time of the question, a signal
   can cancel it, and with `SA_RESTART` the kernel asks a second time. A
   double question breaks `docs/PRODUCT.md` section 5.
3. **Add a user notification listener for a small set of destructive file
   calls**: `unlinkat`, `renameat2`, and `openat` with a write intent. This is
   the part of the gap that the spike really closes. The cost is 1.48× on a
   file workload and 16 µs for each call.
4. **Every allowed call in that set must be emulated, not continued.** The
   supervisor performs the call itself, and gives the result back with
   `ADDFD`. That measured 0 wrong decisions in 6000 opens. This is the only
   configuration that meets the determinism rule of `docs/PRODUCT.md` section
   3. Plan for real work here: the emulation must copy `dirfd`, flags, mode,
   `umask` and symbolic link behaviour exactly.
5. **Mark every event that the firewall cannot emulate as "not
   authoritative".** `connect` and `execve` are in this group. They are good
   for a log line. They are not good for a rule that the documentation calls a
   guarantee.
6. **Do not trap `write` for content inspection.** 8.1× on a write workload,
   and the content has the same race. This is not a QUIET tool at that price.
7. **Make it opt-in, and say why.** `no_new_privs` breaks `sudo`, `su` and
   `pkexec`. Detect the failure and print a clear message from the firewall.

**What would break if `af-monitor` adopts this today:**

- `sudo`, `su`, `pkexec` and 21 other setuid programs stop working in a
  watched session.
- A program in the session that wants its own `seccomp` listener gets `EBUSY`.
- If the monitor process dies, every trapped call in the whole tree returns
  `ENOSYS`, and the programs of the user fail in strange ways. The monitor
  must therefore be at least as reliable as the shell.
- The rules become harder to explain. Today "the firewall stops a program"
  is true. After this change, "the firewall stops a program, and it also stops
  some file operations, and for the file operations that it cannot perform
  itself the answer is only a log line" is the honest text.

**What the documentation must tell the user.** The Agent Firewall stops a
*program* before it runs, and it stops a *file operation* that it can perform
itself. It does not see a statement that a program sends over a connection
that is already open. A user who needs that must use a guard in the database,
and not a guard in the process.
