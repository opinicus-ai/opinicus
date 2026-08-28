# Spike: Linux Landlock

Date: this run. Machine: Fedora 43, kernel `7.0.9-105.fc43.x86_64`, x86_64,
uid 1000, no root, no `sudo`, `kernel.unprivileged_bpf_disabled = 2`.

Everything in Part 1 comes from a program in this directory that I ran. Every
number can be produced again with `make run-all`. Part 2 is an assessment on
paper. It is marked, and it was **not run here**.

---

## Verdict

**Landlock is not a detection mechanism, and it should not be compared with
one. It is the layer that makes a question unnecessary.** It enforces at
**1.0× on all three benchmark workloads** — zero cost within the noise of the
measurement — because the kernel decides in the LSM hook with no supervisor in
the loop, and a ruleset for a work tree is built in 17–26 µs once for each
session. It cannot be escaped: 0 of 6 escape attempts worked, including
granting `/` to itself and re-enacting, a new user namespace, and a fresh
`execve`. It cannot be relaxed, so "allow for this session" is impossible. It
cannot ask, and it sees no program name, no argument, no SQL and no host name.
So it carries exactly the rules whose answer is always no: **10 of the 69
shipping rules move to Landlock with no loss, and all 10 are rules that stop
the user today, which is 24% of the interruption budget.** Twelve more move as
a policy choice, and 47 cannot move because they need what Landlock cannot
see. That is a modest count and a large result, because `docs/PRODUCT.md`
section 5 says the product dies of questions, not of missed attacks: a rule
that never interrupts is worth more than a rule that interrupts well. Landlock
also answers the argument-race that broke `SECCOMP_USER_NOTIF` — it never
reads a path at the moment of a syscall, it fixes the paths before the program
starts — but only for the rules where "no" is always right. **Ship it as an
always-on floor under the monitor, with an explainer for the bare `EACCES`,
and keep `seccomp` for every rule that has to ask.**

---

## What I ran

Every program is C. The spike has its own `Makefile` and it is **not** in the
Cargo workspace, so it cannot take the cargo file lock.

| File | What it does |
| --- | --- |
| `src/landlock_common.h` | the three Landlock system calls through `syscall(2)`, the table of every right with the ABI version that added it, and the ABI detection |
| `src/probe_abi.c` | asks the kernel for the ABI version, the errata mask, and every right one by one. It **never** calls `landlock_restrict_self()`, so it cannot restrict the shell that starts it |
| `src/afw_landlock.c` | the sandbox launcher. It builds a ruleset from the command line, **forks**, applies the ruleset to the child, and the child calls `execvp`. The launcher process is never restricted |
| `src/fs_probe.c` | the target. It runs read, write, create, truncate, unlink, mkdir, rmdir, list, stat, exec, connect and bind, and it prints the error number of each one. The network operations are non-blocking with a 2000 ms poll, so a denied `connect` can never hold a test |
| `src/escape_test.c` | runs inside the sandbox and tries six ways out of it |
| `src/rule_specificity.c` | tests whether a rule deeper in the tree can take a right away |
| `src/tcp_listener.c` | a listener on `127.0.0.1` with its own `alarm()`, so a test can never leave it behind |
| `tests/run-tests.sh` | **58 assertions, all pass.** `make check` |
| `tests/count-rules.py` | reads `policies/*.yaml` and classifies all 69 rules against what Landlock can carry. `make rules` |
| `bench/run-bench.sh` | calls `research/bench/bench.sh --runs 7 --timeout 20` in six configurations. `make bench` |

Everything runs with `make run-all`. Every test and every command is wrapped
in `timeout`. No test ever applies a ruleset to the shell that starts it.

**How the launcher hides a path.** Landlock is an allow list with no deny
rule, so `--hide` cannot be one rule. The launcher walks from the granted
directory down to the hidden one and grants each entry on the way, but never
the hidden path. Section `## The limits` gives the price of that.

---

## The Landlock ABI of this kernel

`bin/probe-abi` asks the kernel with
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`. The
program only asks. It never calls `landlock_restrict_self()`, so it cannot
restrict the shell that starts it.

```
landlock_abi_version           = 8
landlock_errata_bitmask        = 0x7
uid                            = 1000
```

**ABI 8.** That is high. It is above every version that the task named, so
every filesystem right, both network rights, both scopes and the audit log
flags are present.

| Group | Right | Added in ABI | This kernel |
| --- | --- | --- | --- |
| filesystem | `EXECUTE` | 1 | yes |
| filesystem | `WRITE_FILE` | 1 | yes |
| filesystem | `READ_FILE` | 1 | yes |
| filesystem | `READ_DIR` | 1 | yes |
| filesystem | `REMOVE_DIR` | 1 | yes |
| filesystem | `REMOVE_FILE` | 1 | yes |
| filesystem | `MAKE_CHAR` | 1 | yes |
| filesystem | `MAKE_DIR` | 1 | yes |
| filesystem | `MAKE_REG` | 1 | yes |
| filesystem | `MAKE_SOCK` | 1 | yes |
| filesystem | `MAKE_FIFO` | 1 | yes |
| filesystem | `MAKE_BLOCK` | 1 | yes |
| filesystem | `MAKE_SYM` | 1 | yes |
| filesystem | `REFER` (link and rename across a hierarchy) | 2 | yes |
| filesystem | `TRUNCATE` | 3 | yes |
| filesystem | `IOCTL_DEV` | 5 | yes |
| filesystem | `RESOLVE_UNIX` | 9 | **no** |
| network | `BIND_TCP` | 4 | yes |
| network | `CONNECT_TCP` | 4 | yes |
| scope | `ABSTRACT_UNIX_SOCKET` | 6 | yes |
| scope | `SIGNAL` | 6 | yes |
| log flag | `LOG_SAME_EXEC_OFF` | 7 | yes |
| log flag | `LOG_NEW_EXEC_ON` | 7 | yes |
| log flag | `LOG_SUBDOMAINS_OFF` | 7 | yes |

The probe tests each right on its own: it makes a ruleset that handles only
that right, and a right that the kernel does not know gives `EINVAL`.
`RESOLVE_UNIX` is the only one that fails, and the header says it needs ABI 9.
The report is therefore consistent.

Two results matter for the product:

1. **ABI 4 is present, so the TCP tests in part B are possible.**
2. **ABI 7 is present, so a Landlock denial writes an audit record.** That is
   the answer to the "the error is confusing" limit. See `## The limits`.

`landlock_errata_bitmask = 0x7` means the kernel carries the first three
published errata fixes for this ABI.

---

## What it can enforce

58 assertions, all pass, from `./tests/run-tests.sh`. The important ones:

### 1. A write outside the project fails, and a write inside succeeds

Ruleset: `--rw <project>` and nothing else.

| Operation | Result |
| --- | --- |
| `write <project>/inside.txt` | OK |
| `create <project>/new.txt` | OK |
| `mkdir <project>/newdir` | OK |
| `unlink <project>/new.txt` | OK |
| `write <outside>/outside.txt` | **FAIL `EACCES`** |
| `create <outside>/new.txt` | **FAIL `EACCES`** |
| `unlink <outside>/outside.txt` | **FAIL `EACCES`** |
| `read <outside>/outside.txt` | **FAIL `EACCES`** |

The file outside was still on disk with its original content after the run.
The same commands with `--no-sandbox` all succeed, so the denials are the
sandbox and not a broken test.

### 2. Credentials can be made unreadable, and the rest of home stays readable

This is `filesystem.credentials.read` and `filesystem.credentials.write` of
`policies/filesystem.yaml`, carried with no question.

Ruleset: `--ro <home>` with `--hide <home>/.ssh` and
`--hide <home>/.aws/credentials`.

| Operation | Result |
| --- | --- |
| `read <home>/projects/app/main.rs` | OK |
| `read <home>/Documents/notes.txt` | OK |
| `read <home>/.config/settings` | OK |
| `read <home>/.aws/config` | OK — the **non-secret** file beside the secret one |
| `read <home>/.ssh/id_ed25519` | **FAIL `EACCES`** |
| `read <home>/.ssh/known_hosts` | **FAIL `EACCES`** |
| `list <home>/.ssh` | **FAIL `EACCES`** — the directory cannot even be listed |
| `read <home>/.aws/credentials` | **FAIL `EACCES`** |

The write side, with `--rw <home>` and the same two hidden paths:

| Operation | Result |
| --- | --- |
| `write <home>/projects/app/main.rs` | OK |
| `write <home>/.ssh/id_ed25519` | **FAIL `EACCES`** |
| `create <home>/.ssh/backdoor_key` | **FAIL `EACCES`** |
| `write <home>/.aws/credentials` | **FAIL `EACCES`** |
| `unlink <home>/.ssh/known_hosts` | **FAIL `EACCES`** |

The private key file was unchanged on disk after the run.

The carve-out works at **file** granularity: `.aws/credentials` is hidden
while `.aws/config` beside it stays readable.

The same test runs against the **real** `~/.ssh`, read only. Nothing real is
ever written. In the sandbox `list ~/.ssh` gives `EACCES`,
`read ~/.ssh/known_hosts` gives `EACCES`, and `list ~/devel` still gives OK.

One thing Landlock does **not** hide: `stat` on a hidden file still succeeds.
Landlock controls the open, not the metadata. A file name and a file size stay
visible.

### 3. A TCP connect to a port the ruleset does not allow fails

ABI 4 is present, so this test is possible. Two real listeners run on
`127.0.0.1:18101` and `127.0.0.1:18102`, so a denial cannot be mistaken for
"nothing listens there". With no sandbox both answer OK.

Ruleset: `--handle-net --connect-tcp 18101`.

| Operation | Result |
| --- | --- |
| `connect 18101` | OK |
| `connect 18102` | **FAIL `EACCES`** |

With `--handle-net --bind-tcp 18103`: `bind 18103` OK, `bind 18104`
**`EACCES`**.

The error number is the proof. Without Landlock the closed port gives
`ECONNREFUSED(111)`. With Landlock it gives `EACCES(13)`, and no packet ever
leaves.

Landlock ABI 4 only handles TCP `bind` and `connect`, **by port number only**.
There is no rule on an address, and there is no rule for UDP. `network.yaml`
needs both a host and a port, so Landlock cannot carry those rules as written.

### 4. The restriction is inherited by children and grandchildren

`sh -c 'sh -c "sh -c ..."'`, three shells deep:

| Operation at depth 3 | Result |
| --- | --- |
| `read <outside>/outside.txt` | **FAIL `EACCES`** |
| `read <project>/inside.txt` | OK |
| `cat <outside>/outside.txt` | `Permission denied` |
| `rm -rf <outside>` | the tree was **still there** afterwards |

That last row is the answer to the open question of `docs/PRODUCT.md` section
6, from the other side. Exec-only `ptrace` cannot see a delete inside a
running program. Landlock does not need to see it, because the delete cannot
happen.

### 5. The target cannot remove the restriction

`bin/escape-test` runs inside the sandbox and tries six ways out. **0 of 6
worked.**

| Attempt | Result |
| --- | --- |
| make a new ruleset that grants every right on `/`, then `landlock_restrict_self` again | `restrict_self` returned OK, and the read **still fails**. A new layer can only intersect |
| find any call that drops the domain | none. Every unknown flag of `landlock_create_ruleset` gives `EINVAL` |
| `execve` a fresh `/bin/cat` on the secret | denied, `cat` exited 1 |
| `unshare(CLONE_NEWUSER)` and read again | the namespace was created, and the read still fails |
| turn `no_new_privs` off with `prctl` | `EINVAL`. The flag stays 1 |
| hard-link the secret into a writable directory | `link()` failed with `EXDEV`, "Invalid cross-device link". The two paths are on the same file system; Landlock reports a cross-device link because the `REFER` right does not cover the pair |

This is the opposite of `LD_PRELOAD`, which the baselines thread showed a
target defeats with one word. A Landlock domain is on the kernel task struct.
Nothing in user space can reach it.

---

## Measured cost

`./research/bench/bench.sh --runs 7 --timeout 20 -- bin/afw-landlock ...`,
median wall clock in ms. The workloads need four grants to run at all:
`--rx /usr --rx /etc --rw /tmp --rw /dev/null`. `/tmp` because the harness
makes its working directory there, and `/dev/null` because the workloads
redirect to it. Nothing had to be loosened beyond that.

| Wrapper | W1 exec | W2 file | W3 mixed |
| --- | --- | --- | --- |
| none (task baseline) | 145 ms | 13 ms | 83 ms |
| none (my session baseline) | 157 ms | 14 ms | 85 ms |
| `afw-landlock --no-sandbox` (fork and exec only) | 154 ms (0.98×) | 15 ms (1.07×) | 87 ms (1.02×) |
| **minimal file ruleset, 4 rules** | **156 ms (0.99×)** | **14 ms (1.00×)** | **89 ms (1.05×)** |
| minimal plus TCP handled, no port allowed | 154 ms (0.98×) | 14 ms (1.00×) | 89 ms (1.05×) |
| minimal plus the home carve-out, 209 rules | 160 ms (1.02×) | 17 ms (1.21×) | 87 ms (1.02×) |
| everything: fs, net and the signal scope | 160 ms (1.02×) | 14 ms (1.00×) | 87 ms (1.02×) |
| write-xor-execute: `/tmp` writable, no execute | 153 ms (0.97×) | 14 ms (1.00×) | 86 ms (1.01×) |

**The claim holds. The cost of enforcement is zero within the noise of the
measurement.** Every ratio is between 0.98× and 1.07×, and the run-to-run
spread of the unwrapped baseline is of the same size. There is no supervisor
in the loop: the kernel walks the rule in the LSM hook and returns.

Compare with the siblings on the same harness:

| Mechanism | W1 exec | W2 file | W3 mixed | Can it block? | Can it ask? |
| --- | --- | --- | --- | --- | --- |
| **Landlock** | **1.0×** | **1.0×** | **1.0×** | yes | **no** |
| `seccomp` + `RET_TRACE` | 1.5× | 1.2× | 1.3× | yes | yes |
| `SECCOMP_USER_NOTIF`, full set | 1.21× | 1.48× | 1.36× | yes | yes |
| full `PTRACE_SYSCALL` | 2.9× | 8.3× | 3.0× | yes | yes |

The one cost that is real is the **build** of the ruleset, and it is paid once
for each sandboxed process, before `execve`:

| Ruleset | Rules | Build time |
| --- | --- | --- |
| project only: `/usr`, `/etc`, `/tmp`, `/dev/null` | 4 | **17–26 µs** |
| the same plus a carve-out of the real `$HOME` around `~/.ssh` | 209 | **691–1090 µs** |
| a carve-out of a small home around `.ssh` and `.aws/credentials` | 7 | 62 µs |

One millisecond for the worst case, once for each agent session. That is
nothing beside the 145 ms of W1.

The reason the carve-out is expensive is that it needs one rule for each entry
of every directory on the way to the hidden path. A large `$HOME` therefore
costs more rules. The fix is not to grant `$HOME` at all, and to grant the
project directory instead.

---

## The limits

### 1. It cannot ask

There is no notification path in Landlock. The API has three system calls:
`landlock_create_ruleset`, `landlock_add_rule` and `landlock_restrict_self`.
None of them takes a file descriptor on which a supervisor could wait. The
kernel decides in the LSM hook and returns. **A denied run in the test set
took 2 ms end to end, because nothing waited for anybody.**

The consequence is sharp:

> **Landlock can carry a rule where the answer is always no. It cannot carry a
> rule where the answer is "it depends".**

`docs/PRODUCT.md` section 5 says that too many questions kill the product.
Landlock does not answer that problem by asking better. It answers it by
removing the question. That is the whole value, and it is also the whole
limit. Every rule with `decision: approval_required` that a user sometimes
says yes to must stay with `seccomp` or `ptrace`.

### 2. It cannot be relaxed at run time

Measured, from `bin/escape-test` inside the sandbox:

* A second ruleset that grants **every right on `/`** was created and enacted.
  `landlock_restrict_self` returned success. The forbidden read **still
  failed**. A new ruleset is a new layer, and the layers intersect. A layer
  can only take rights away.
* There is no call that removes a domain. Every flag value of
  `landlock_create_ruleset` other than `VERSION` and `ERRATA` gives `EINVAL`.
* `no_new_privs` cannot be turned off: `prctl(PR_SET_NO_NEW_PRIVS, 0)` gives
  `EINVAL` and the flag stays 1.

**What this means for "allow for this session".** A session cannot start
locked and open after an approval. If the user approves an action at minute
ten, the process that is already running can never be given the right. The
only ways out are:

1. Decide the rights **before** the process starts, from the task. A session
   that is going to touch `~/.aws` must be started with `~/.aws` granted.
2. Start a **new** process for the approved action, with a wider ruleset. The
   firewall already starts processes, so this is possible, but the approved
   action then runs in a different process than the one that asked.
3. Keep the "it depends" rules out of Landlock. This is the honest answer, and
   it is the one the recommendation below takes.

### 3. It has no deny rule, and a right cannot be taken back deeper in the tree

Measured, from `bin/rule-specificity`:

| Attempt | Result |
| --- | --- |
| a rule with `allowed_access = 0` on the subtree | refused, `ENOMSG` |
| a narrow rule (`MAKE_SYM` only) on the subtree, under a broad rule on the parent | accepted, **and the subtree was still listable** |

A right that a rule gives on a directory reaches every file under it, and a
rule deeper in the tree can only add. So `--hide` must **enumerate**: it walks
from the granted directory down to the hidden one and grants each entry on the
way, but never the hidden path.

The price is visible: **the directory that holds a hidden path cannot be
listed any more**, because it gets no rule of its own. In the tests,
`--ro $HOME --hide $HOME/.ssh` makes `ls ~` fail while `ls ~/devel` still
works. The carve-out also costs 209 rules and about 1 ms for a real `$HOME`.

The product answer is not to grant `$HOME` at all. Grant the work tree, and
add the few paths that the task needs.

### 4. What it cannot see

Landlock sees a **path** and a **TCP port number**. It sees nothing else.

| The rule pack needs | Landlock has |
| --- | --- |
| the program name (`rm`, `psql`, `kubectl`) | nothing. It sees only which file is executed, by hierarchy |
| the command arguments (`--force`, `-rf`, `--no-preserve-root`) | nothing |
| SQL statement text (`DROP DATABASE customer_prod`) | nothing |
| a git verb (`push --force`, `reflog expire`) | nothing |
| a host name (`db.prod.internal`) | nothing. ABI 4 rules carry a **port number only**, for every address |
| the process chain (an interpreter that a download tool started) | nothing |
| file mode bits (`chmod 777`) | nothing |
| file metadata | nothing. **`stat` on a hidden file still succeeds**, measured |

The test set shows the last point of the table twice: `rm -rf ./newdir` inside
the work tree is allowed, and the string `git push --force` is only bytes to
Landlock.

### 5. The error is confusing

A denied action gives a plain `EACCES(13)`, "Permission denied". There is no
reason, no rule name and no hint that a firewall is involved. A developer sees
`cat: /home/me/.ssh/id_ed25519: Permission denied` and blames the file mode,
or blames the firewall for something it did not do.

Three ways the firewall can explain the denial after the fact. The first is
measured, the other two follow from the sibling threads:

1. **The launcher already knows.** `afw-landlock` builds the ruleset, so it
   holds the list of granted paths. When the child exits non-zero, the
   firewall can match the failing path against its own grant list and say "the
   sandbox denied this, because of the rule `filesystem.credentials.read`".
   This costs nothing and needs no privilege.
2. **The monitor can watch the failing call.** The `seccomp` `RET_TRACE`
   thread measured file and network visibility at 1.2×–1.3×. A filter that
   traps `openat` and `connect` sees the call that is about to fail, and the
   monitor can then print the reason next to the `EACCES`. The trap is for the
   **message**, not for the decision, so the argument race that broke
   `SECCOMP_USER_NOTIF` does not matter here: a wrong path in a log line is a
   cosmetic error, and the enforcement was already correct.
3. **The kernel writes an audit record.** This kernel is ABI 8, so the ABI 7
   log flags of `landlock_restrict_self` are present, and this kernel reports
   them as supported. A Landlock denial therefore reaches the audit
   subsystem. **I could not read the record**, because `auditd` runs on this
   machine and reading its log needs `CAP_AUDIT_READ` or root, and I am uid
   1000. So option 3 is real but it belongs in the privileged tier. Options 1
   and 2 need no privilege and should be built first.

---

## How much of the rule pack could move to Landlock

`make rules` runs `tests/count-rules.py`. The script reads `policies/*.yaml`,
and it fails if a rule in the pack has no class, so the count cannot drift
away from the rule pack.

The pack holds **69** rules: **41** stop the user (`deny` or
`approval_required`) and **28** only report. That matches
`docs/PRODUCT.md` section 5.

Three classes:

* **A — Landlock removes the question.** The rule stops the user today,
  Landlock can make the action impossible before the program starts, and
  normal work does not need the action.
* **B — Landlock removes the damage, but the move is a choice.** The rule only
  reports today, or Landlock covers part of the ground, so the move changes
  what a developer can do.
* **C — Landlock is blind.** The rule matches a program name, an argument, SQL
  text, a host name or a file mode.

| Policy file | Rules | A | B | C |
| --- | ---: | ---: | ---: | ---: |
| `allowlist.yaml` | 5 | 0 | 2 | 3 |
| `cloud.yaml` | 14 | 0 | 1 | 13 |
| `database.yaml` | 11 | 0 | 0 | 11 |
| `filesystem.yaml` | 14 | **9** | 2 | 3 |
| `git.yaml` | 9 | 0 | 1 | 8 |
| `network.yaml` | 7 | 0 | 3 | 4 |
| `process.yaml` | 9 | **1** | 3 | 5 |
| **TOTAL** | **69** | **10** | **12** | **47** |

### The headline number

**10 of the 69 rules move to Landlock with no loss. All 10 are rules that stop
the user today, so the interruption budget drops by 10 of 41, which is 24%.**
Twelve more can move as a policy choice. Forty-seven cannot move at all.

### Class A — 10 rules, the question disappears

| Rule | Decision today | Why Landlock carries it |
| --- | --- | --- |
| `filesystem.delete.root` | deny | no `REMOVE_*` right on `/` |
| `filesystem.delete.home` | approval | the home directory is not granted write |
| `filesystem.delete.system-path` | approval | `/etc`, `/usr`, `/var` are read and execute only |
| `filesystem.delete.parent-directory` | approval | only the work tree is granted, and `..` is outside it |
| `filesystem.credentials.write` | approval | **measured**: write and create in `.ssh` give `EACCES` |
| `filesystem.sensitive.exec-write` | approval | the effect is that write, and that write is impossible |
| `filesystem.etc.write` | approval | `/etc` is read and execute only |
| `filesystem.device.destroy` | deny | `/dev/sd*` is not granted |
| `filesystem.device.truncate` | approval | `TRUNCATE` (ABI 3) is handled and never granted on a device |
| `process.signal.kill-everything` | approval | **measured**: `LANDLOCK_SCOPE_SIGNAL` (ABI 6) gives `EPERM` outside the sandbox |

Notice the shape: **9 of the 10 are in one file.** Landlock is a filesystem
mechanism with a small network and IPC extension, and the rule pack is mostly
about programs and their arguments. The win is concentrated, not spread.

### Class B — 12 rules, the move is a policy choice

The best three, because they turn a report into an impossibility:

* `process.exec.from-temp` and `process.perm.executable-in-temp`. **Measured**:
  with `/tmp` granted write and no execute, a program copied into `/tmp` gives
  `EACCES` on `exec`, while a write to the same directory still works. That is
  write-xor-execute for the agent, and it costs nothing on the benchmark
  (W1 153 ms, W2 14 ms, W3 86 ms with `--rw-noexec /tmp`).
* `filesystem.credentials.read`. **Measured**: the read gives `EACCES` while
  `.aws/config` beside the secret file stays readable.
* `process.persistence.autostart`. `crontab`, `~/.config/systemd` and
  `~/.bashrc` are outside the work tree, so they can be read only.

The rest are partial: `network.connect.remote-admin` and
`network.connect.remote-database` can be denied by **port**, but the rules
exclude `localhost` and Landlock has no address rule, so the move would also
stop a local `ssh` or a local `psql`. `cloud.kubectl.production-context` can be
carried by hiding a production kubeconfig file, but that also stops a
read-only `kubectl` against it.

### Class C — 47 rules, out of reach

| Reason | Rules |
| --- | ---: |
| the rule needs the program name or its arguments | 27 |
| the action is statement text inside a client program | 9 |
| the path is inside the work tree, which must stay writable | 6 |
| the rule needs a host name or an address | 2 |
| the rule needs the process chain | 2 |
| the rule needs file mode bits | 1 |

The third row is the interesting one. `filesystem.delete.git-directory`,
`git.history.rewrite`, `git.local.discard-work`, `git.refs.delete`,
`git.history.drop-recovery` and `filesystem.dotenv.write` all act **inside**
the directory that the developer is working in. A sandbox that stops them
stops the work. These rules need a question, and a question needs `seccomp`.

---

## The privileged tier

**NOT RUN HERE.** Everything in this section is an assessment on paper. I am
uid 1000, `sudo` is not available, and `kernel.unprivileged_bpf_disabled = 2`
closes eBPF completely. I ran no eBPF program, no `fanotify` permission event,
no audit rule and no `proc` connector socket.

Four facts about this machine are measured, and they change the assessment:

```
/sys/kernel/security/lsm     lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
/proc/cmdline                (no lsm= parameter at all)
/sys/kernel/btf/vmlinux      present, 6.9 MB
perf_event_paranoid          2
unprivileged_bpf_disabled    2
SELinux                      Enforcing
auditd                       already running
```

`bpf` is in the active LSM list with **no `lsm=` boot parameter**, so Fedora 43
ships it in `CONFIG_LSM`. A BPF LSM tier would need no boot change on this
distribution. BTF is present, so CO-RE works. And `auditd` already runs, which
makes the audit conflict below real and not theoretical.

### 1. eBPF LSM hooks (`BPF_PROG_TYPE_LSM`)

| | |
| --- | --- |
| Block or observe | **Block.** A program on a `lsm/` hook returns a non-zero errno and the kernel refuses the operation |
| Privilege | `CAP_BPF` + `CAP_PERFMON` since kernel 5.8; `CAP_SYS_ADMIN` before that |
| Kernel need | `CONFIG_BPF_LSM=y`, BTF, and `bpf` in the active LSM list. **Present on this machine with no boot change** |

**Why it beats `seccomp`, and this is the whole point.** A `seccomp` filter
sees the raw syscall arguments, and for `open` the path argument is a
**pointer into the memory of the target**. That is the race the sibling thread
measured at 47.6% wrong. A BPF LSM program on `lsm/file_open` receives a
`struct file *`: a kernel object that the kernel has **already resolved** from
the path. The program and the kernel look at the same object, so the race
cannot exist. KP Singh raised exactly this point when he presented KRSI
(<https://lwn.net/Articles/798157/>); the sibling measurement is the proof
that the concern was right.

**It cannot ask either.** This is the fact most likely to be got wrong. BPF
LSM programs can be "sleepable" since kernel 5.11, and the name suggests a
wait. It does not mean that. "Sleepable" means the program may page-fault and
take a sleeping lock **inside the kernel**. There is no path that blocks the
hook until a user-space daemon answers. The decision must be inline, from
data that user space put in a BPF map before the event.
(<https://docs.kernel.org/bpf/prog_lsm.html>)

**So eBPF LSM is a better Landlock, not a better `seccomp`.** It removes
Landlock's two worst limits — it can match on more than a path hierarchy, and
it covers hooks Landlock has no right for — while keeping the "no question"
property. It does **not** give the product an approval path.

Overhead: the KRSI benchmark showed about 4% for a no-op LSM hook against a
28% figure for audit with rules, on a kernel 5.2 era prototype
(<https://lwn.net/Articles/798157/>). Treat that as indicative only.

Install friction: `CAP_BPF` + `CAP_PERFMON` through a systemd unit or a
`setcap` helper. On this machine SELinux is Enforcing, so loading a BPF
program also needs the SELinux `bpf` class permission. Medium friction.

### 2. eBPF tracepoints and kprobes

| | |
| --- | --- |
| Block or observe | **Observe only.** The event fires and the process continues |
| Privilege | `CAP_BPF` + `CAP_PERFMON` since 5.8; `perf_event_paranoid` is 2 here, which blocks an unprivileged attach (<https://man7.org/linux/man-pages/man2/perf_event_open.2.html>) |

**What it adds is provenance, and provenance is the thing the product sells.**
`docs/PRODUCT.md` section 2 says the value is the causal chain.
`sched:sched_process_fork`, `sched:sched_process_exec` and
`sched:sched_process_exit` give the full parent chain of **every** process on
the machine with **no misses**, against the 99.7% miss rate a sibling thread
measured for `/proc` polling. It also gives the cgroup id, and therefore the
container, through `bpf_get_current_cgroup_id()`.

One trap: `syscalls:sys_enter_execve` delivers `argv` as a **user-space
pointer**, so reading it with `bpf_probe_read_user_str()` has the same race as
`seccomp`. For race-free `argv` the right hook is `lsm/bprm_check_security`,
which receives a `struct linux_binprm *` the kernel already built.

Falco's `modern_ebpf` driver, Tetragon and Tracee all take this route
(<https://falco.org/blog/falco-modern-bpf/>). Kprobes are explicitly not a
stable ABI (<https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html>);
the `sched:sched_process_*` tracepoints are stable in practice.

This is the **cheapest** privileged win: observation only, so no new failure
mode for the user, and it fixes the one thing exec-only `ptrace` cannot do —
see a process the firewall did not start.

### 3. `fanotify` with `FAN_OPEN_PERM`

| | |
| --- | --- |
| Block or observe | **Block, and it can hold the process while it asks.** The target blocks in the kernel until the listener writes `FAN_ALLOW` or `FAN_DENY` |
| Privilege | `CAP_SYS_ADMIN`. Not negotiable |
| Kernel need | `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`, which the task confirms is set here |

**The argument-reliability question, which is the important one.** `fanotify`
does **not** have the race that broke `SECCOMP_USER_NOTIF`. I checked the man
page directly. The event carries a file descriptor, not a pointer:

> *fd* — "This is an open file descriptor for the object being accessed... The
> file descriptor can be used to access the contents of the monitored file or
> directory."
> (<https://man7.org/linux/man-pages/man7/fanotify.7.html>)

The kernel resolved the path to an object **before** it made the event, and it
handed the listener a reference to that object. `fstat(event->fd)` or
`readlink("/proc/self/fd/N")` therefore names the file the kernel is about to
open, and no other thread can change it. The same page also notes that the
kernel sets `FMODE_NONOTIFY` on that description, so the listener does not
make new events when it reads through it.

**This is the single most valuable fact in this section.** The sibling thread
showed that a path read from the target's memory is not a sound basis for a
decision. `fanotify` gives the supervisor the object itself. It is the
`ADDFD` trick of the `seccomp` thread, but built into the mechanism instead of
worked around.

Four cautions, all from the same page or the `fanotify_init(2)` page:

* `FAN_REPORT_FID` and the other file-handle modes **cannot** be combined with
  permission classes; `fanotify_init` gives `EINVAL`. So a permission listener
  pays one open descriptor for each event and must close it.
* Unprivileged `fanotify` (kernel 5.13) explicitly **cannot request permission
  events**. There is no unprivileged version of this.
* Deadlock is real. If the listener opens one of its own files on a watched
  filesystem while it holds an unanswered event, it waits for itself. Keep the
  listener's own files off the watched mount, or use `FAN_MARK_IGNORED_MASK`.
* **`fanotify` is filesystem only.** It sees no `connect`, no `execve` argv and
  no SQL. It would carry the class A and class B **file** rules and nothing
  else.

One thing I could **not** settle. `fanotify(7)` says a pending permission
event lives "until either a permission decision has been taken ... or the
fanotify file descriptor is closed", but it does not say what the kernel does
to the held access when the descriptor closes. My research found sources that
claim deny and sources that claim allow, in the same breath. **This is a
fail-open or fail-closed question and it must be settled in the kernel source
before anybody ships it.** There is also no timeout: a listener that stops
answering holds every watched file open on the machine. That is a serious
operational risk for a developer tool and it argues for a narrow mark set.

Install friction: a root systemd unit. This is exactly how on-access antivirus
ships, so it is a familiar shape for a company. Low friction for an
enterprise, unacceptable for an individual developer.

### 4. The audit subsystem

| | |
| --- | --- |
| Block or observe | **Observe only.** There is no decision path at all |
| Privilege | `CAP_AUDIT_CONTROL` to set rules, `CAP_AUDIT_READ` to read the multicast stream |

**Yes, this is an enterprise integration and not an enforcement path.** Three
reasons.

1. It cannot block. Nothing in the audit API holds a process.
2. Only one process can hold the `audit_pid` unicast connection. **`auditd`
   already runs on this machine.** A product that takes `audit_pid` breaks the
   company's existing audit pipeline, which is the fastest way to be
   uninstalled by the security team. Reading is safer: since kernel 3.16 a
   process with `CAP_AUDIT_READ` can join the multicast group and get a copy
   without touching `audit_pid`.
3. The cost is high. The KRSI benchmark put audit with `execve` rules at about
   28% (<https://lwn.net/Articles/798157/>), against about 4% for a BPF LSM
   hook.

Its argument capture is also weak: `a0`–`a3` are raw register values, so a
pointer argument is an address and not a string, and `execve` argv capture is
truncated.

**The right shape is the opposite direction.** Do not read audit. Write to it.
Ship the firewall's own decisions into the company's existing `auditd` and
SIEM as an `audisp` plugin. That needs no new privilege, it breaks nothing,
and it is the feature an enterprise buyer actually asks for.

**One use that does matter here.** ABI 7 makes the kernel write an audit
record for a Landlock denial. In the privileged tier, reading that record is
the cleanest way to turn a bare `EACCES` into "the firewall denied this". That
connects limit 5 above to this tier.

### 5. The `proc` connector netlink

| | |
| --- | --- |
| Block or observe | **Observe only, and after the fact.** `PROC_EVENT_EXEC` arrives when the new program is already running |
| Privilege | `CAP_NET_ADMIN`, for the netlink multicast bind |

**It is worse than what the product already ships.** Exec-only `ptrace` needs
**no** capability for the agent's own children, and it **holds** the process
before it runs, which is what a decision needs. The connector needs
`CAP_NET_ADMIN`, and it cannot hold anything.

It is also thin. The exec event carries `process_pid` and `process_tgid` and
nothing else: no file name, no `argv`. To get the command line you must read
`/proc/<pid>/cmdline` afterwards, which races the process exit — the same race
that gave the `/proc` polling thread its 99.7% miss rate. It is better than
polling, because the kernel pushes the event instead of the monitor guessing
when to look, but it is well behind `ptrace` and far behind eBPF tracepoints.

Two more limits worth stating. Netlink has no back pressure, so events are
dropped under load and the connector documentation says so
(<https://www.kernel.org/doc/Documentation/connector/connector.txt>). And the
kernel gates the subscription on the initial user and PID namespaces, so a
container gets nothing.

`CAP_NET_ADMIN` also lets a process reconfigure the network. Asking a user for
it to watch processes is over-privileged for what it returns.

**Verdict: do not build this.** eBPF tracepoints do the same job better, for a
capability that is at least about tracing.

### The tier, ranked

| Mechanism | Blocks? | Asks? | Privilege | What it adds | Build it? |
| --- | --- | --- | --- | --- | --- |
| eBPF tracepoints | no | no | `CAP_BPF`+`CAP_PERFMON` | complete, zero-miss provenance for every process on the machine | **yes, first** |
| `fanotify` `FAN_OPEN_PERM` | yes | **yes** | `CAP_SYS_ADMIN` | the only privileged path that can ask, with a race-free object | **yes, second** |
| eBPF LSM | yes | no | `CAP_BPF`+`CAP_PERFMON` | a Landlock without Landlock's blind spots; race-free arguments | yes, third |
| audit | no | no | `CAP_AUDIT_READ` | an enterprise pipeline, and a reason for a Landlock `EACCES` | as an integration only |
| `proc` connector | no | no | `CAP_NET_ADMIN` | less than `ptrace` already gives | **no** |

---

## The layered recommendation

The product answer is not one mechanism. Each of the four threads measured a
different property, and no mechanism has all of them.

| | can block | can ask | sees arguments | cost | privilege |
| --- | --- | --- | --- | --- | --- |
| exec `ptrace` (ships today) | yes, at exec | yes | **yes**, `argv` at the stop | ~1.0× | none |
| **Landlock** | **yes** | **no** | no | **1.0×** | **none** |
| `seccomp` `RET_TRACE` | yes | yes | yes, with a race | 1.2×–1.3× | none |
| `SECCOMP_USER_NOTIF` | yes | yes | **no, 47.6% wrong** | 1.2×–1.5× | none |
| full `PTRACE_SYSCALL` | yes | yes | yes | 2.9×–8.3× | none |

Landlock is the only row with a zero in the cost column and a yes in the block
column. It is also the only row with a **no** under "can ask". That pair
decides where it belongs.

### Layer 0 — impossible. Landlock. No question, no cost. Always on.

**10 rules of 69, and 10 of the 41 that stop the user today.**

Grant the work tree, `/usr`, `/etc` read-only, `/tmp` write with no execute,
and the few paths the task needs. Carve out `~/.ssh`, `~/.aws/credentials`,
`~/.netrc` and `~/.git-credentials`. Handle the signal scope.

What that buys, all measured in this spike:

* `rm -rf /`, `rm -rf ~`, `rm -rf /etc` and `rm -rf ..` cannot run. Not
  "are asked about" — **cannot run**, three shells deep, from any program,
  whether or not the firewall recognised the command.
* A credential file cannot be read or written, and the file beside it stays
  readable.
* A raw write to a disk device cannot happen.
* `kill -9 -1` cannot reach the user's editor.
* A program dropped in `/tmp` cannot start.
* Cost: **1.0× on all three workloads.** Ruleset build: 17–26 µs for a
  work-tree ruleset, paid once for each session.

This is the layer that answers `docs/PRODUCT.md` section 5 directly. It does
not make the question better. It deletes the question. **Quiet is the
feature, and this is the quietest mechanism there is.**

It is also the answer to the argument-race result of the `seccomp` user
notification thread. That thread showed a path read at the moment of a syscall
cannot be trusted. Landlock never reads a path at the moment of a syscall. It
fixes the paths **before the program starts**, when nothing is racing, and the
kernel then compares its own resolved object against them. The unsound step
does not exist.

### Layer 1 — ask. `seccomp` `RET_TRACE`, on the existing monitor. Default on.

The rules where the answer is "it depends" and the damage is inside the work
tree, or the damage is named by an argument.

* the 6 class C rules that act inside the work tree — `.git` deletion, history
  rewrite, discarding work, `.env` writes
* the file and network rules that need a host name
* every rule that today needs `argv` at the exec boundary

`RET_TRACE` costs 1.2×–1.3×, and the sibling thread showed it keeps the whole
existing monitor design. Use it for the **question**, not for the decision on
a path: for a path decision the argument is not trustworthy, and Landlock has
already made the worst paths impossible anyway.

Do **not** use `SECCOMP_USER_NOTIF` for a path decision. The 47.6% figure
settles it. Use it only where the supervisor supplies the object itself, as
that thread showed with `ADDFD`.

### Layer 2 — record. Exec `ptrace`, which already ships. Always on.

The 28 report-only rules, and the provenance chain behind every decision of
layer 0 and layer 1.

This layer also carries the fix for Landlock's worst usability problem. When
the sandbox denies something, the target sees a bare `EACCES` and blames the
firewall. The launcher holds the grant list, so it can name the rule that
caused the denial. That costs nothing and needs no privilege, and it should be
built at the same time as layer 0. Without it, layer 0 will be turned off by
the first developer who cannot work out why `cat` failed.

### Layer 3 — the privileged tier. Optional. Off by default.

`docs/PRODUCT.md` section 3 says a product that needs root will not be
installed. So this layer must never be required, and the product must be fully
useful without it. For a company that accepts an installer, in order:

1. **eBPF tracepoints** (`CAP_BPF` + `CAP_PERFMON`). Complete process
   provenance for every process on the machine, not only the children the
   firewall started. It closes the 99.7% miss rate of `/proc` polling. It
   blocks nothing, so it adds no new way to break a developer's day. On this
   machine BTF is present and `bpf` is already in the LSM list, so the only
   real friction is the capability and the SELinux permission.
2. **`fanotify` `FAN_OPEN_PERM`** (`CAP_SYS_ADMIN`). The only privileged path
   that can **hold a file open and ask**, and the event carries a file
   descriptor instead of a pointer, so the decision is race-free. It would
   move part of layer 1 out of `seccomp`. Two things must be settled first:
   what the kernel does with pending events when the listener dies, and the
   fact that there is no timeout.
3. **eBPF LSM** (`CAP_BPF` + `CAP_PERFMON`). A Landlock without Landlock's
   blind spots, with kernel objects instead of user pointers. It still cannot
   ask, so it extends layer 0 and not layer 1.
4. **audit**, as an outbound integration only. Write the firewall's decisions
   into the company's existing `auditd` and SIEM. Do not take `audit_pid`.
5. **`proc` connector — do not build it.** It needs `CAP_NET_ADMIN`, it cannot
   hold a process, and it carries no `argv`. It is behind the `ptrace` the
   product already has.

### What to do next

1. Put the layer 0 ruleset behind one setting, default on, and ship the
   `EACCES` explainer with it in the same release. The explainer is not
   optional; it is what keeps the setting on.
2. Do not grant `$HOME`. Grant the work tree. The carve-out of a real `$HOME`
   costs 209 rules, and it stops `ls ~` from working.
3. Move the 10 class A rules from `approval_required` to "enforced by the
   sandbox" in the rule pack, and keep their tests. The rule stays; only the
   mechanism changes.
4. Treat the 12 class B rules as a second switch, "strict mode". Start with
   `process.exec.from-temp`, because write-xor-execute for `/tmp` is free and
   it removes a whole class of attack.
