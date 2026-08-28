# Linux research questions and answers

PROJECT.md section 10 asks whether a user-space monitor can do the work of an
agent firewall on Linux. This document gives the answers. Every answer comes
from a measurement on the development machine, and a test in the workspace
keeps the answer true.

Machine of the measurements:

| Item | Value |
| --- | --- |
| Operating system | Fedora Linux 43, kernel 7.0.9, `x86_64` |
| Toolchain | Rust 1.97.1 |
| `/proc/sys/kernel/yama/ptrace_scope` | `0` |
| Privileges | a normal user, no root, no capability, no container |

---

## 1. Process monitoring without root

**Question.** Can the program observe process creation, fork, clone, execve,
process exit, the parent identifier, the executable path, the arguments and
the working directory without root?

**Answer: yes, all of it.**

The monitor launches the program under `ptrace` and sets these options on the
root process:

```
PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE
PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT  | PTRACE_O_EXITKILL
```

The kernel gives each event to the monitor at a stop. `/proc/<pid>/cmdline`,
`/proc/<pid>/exe`, `/proc/<pid>/cwd`, `/proc/<pid>/stat` and
`/proc/<pid>/environ` give the facts.

`PTRACE_O_EXITKILL` is important for safety. It tells the kernel to kill every
tracee when the monitor dies. Without it, a crash of the firewall can leave a
stopped process for ever.

Yama only limits `PTRACE_ATTACH`. It does not limit a child that calls
`PTRACE_TRACEME`, so the launch path works even when `ptrace_scope` is `1`.

*Test:* `af-monitor` `simple_session_reports_exec_and_exit`,
`read_process_*`, `process_facts_of_the_monitor_itself_are_complete`.

---

## 2. Descendant tracking

**Question.** If the monitored process creates
`agent -> bash -> python -> shell -> psql`, can the monitor connect every
process to the original session?

**Answer: yes, with no gap and no race.**

`PTRACE_EVENT_FORK`, `PTRACE_EVENT_VFORK` and `PTRACE_EVENT_CLONE` report the
new process identifier through `PTRACE_GETEVENTMSG` **before the new process
runs**. The monitor therefore learns about a child earlier than any reader of
`/proc` can, and a short-lived grandchild cannot escape.

A thread is a clone that shares the address space. The monitor reads `Tgid:`
in `/proc/<tid>/status` to separate a thread from a process. This needs no
register read, so the code stays free of architecture details.

The cost is about two stops for each process. That is invisible next to the
speed of a coding agent.

*Test:* `af-monitor` `nested_session_links_every_child_to_the_root`,
`a_program_with_threads_and_many_children_stays_complete`,
`target_scenario_finds_psql_with_its_full_provenance`.

---

## 3. Attach compared with launch

**Question.** Which path is better?

**Answer: launch.**

| | Launch | Attach |
| --- | --- | --- |
| First `execve` of the agent | always seen | often missed |
| Race at start | none | always |
| Yama `ptrace_scope=1` | works | refused |
| Children that already exist | none to find | must be found one by one |

`PTRACE_TRACEME` in the child, before `execve`, cannot miss anything.
`PTRACE_ATTACH` always races against the process that it wants to watch.

**A deviation from the plan.** The first design called `PTRACE_TRACEME` and
then `raise(SIGSTOP)` inside `pre_exec`. That deadlocks for ever.
`Command::spawn` blocks while it reads the close-on-exec error pipe of the
child, and a child that stops before `execve` never closes that pipe. A helper
thread does not help, because `PTRACE_TRACEME` binds to the thread that forks.

The fix is to call only `PTRACE_TRACEME`. The kernel closes the error pipe
during `begin_new_exec`, which happens **before** it raises the `SIGTRAP` after
the exec. So `spawn` returns, and the first `waitpid` lands on a stop that is
the same as an exec stop: the image is loaded and no instruction has run. The
monitor sets the options at that stop.

---

## 4. Data access

**Question.** Which data can the monitor collect, and from where?

| Data | Source | Available |
| --- | --- | --- |
| Process creation, exec, exit | `ptrace` stops | yes |
| Parent identifier | event order, `/proc/<pid>/stat` | yes |
| Executable path | `/proc/<pid>/exe` | yes |
| Command line | `/proc/<pid>/cmdline` | yes |
| Working directory | `/proc/<pid>/cwd` | yes |
| Start time, for identifier reuse | field 22 of `/proc/<pid>/stat` | yes |
| Environment | `/proc/<pid>/environ` | yes, filtered |
| Thread or process | `Tgid:` in `/proc/<pid>/status` | yes |
| File open events | needs `PTRACE_SYSCALL`, `fanotify` or eBPF | no |
| Network connect events | needs `PTRACE_SYSCALL`, eBPF or a netlink hook | no |

The monitor keeps only environment names from an allow list, and it replaces
the value of any name that holds `PASSWORD`, `TOKEN`, `SECRET`, `KEY`,
`CREDENTIAL` or `AUTH` with `<redacted>`. A rule can still use the presence of
a name.

`PTRACE_SYSCALL` would give file and network events, but it stops the tracee
twice for every system call. That cost is too high for a tool that must stay
quiet on a developer machine. `fanotify` and eBPF need privileges, so they
belong to the later "privileged integrations" level of the product.

A field-22 start time makes a `ProcessKey` that survives identifier reuse.
Linux reuses a process identifier, and a provenance chain that ignores this
can join two different processes.

---

## 5. Blocking

**Question.** Can the monitor intercept an exec before execution, suspend the
process, inspect the action, wait for approval, resume, or end it safely?

**Answer: yes. This is real prevention, not only a report.**

`PTRACE_EVENT_EXEC` stops the tracee after the kernel loads the new program
image and **before the new program runs one instruction**. At that stop the
monitor has the full command line and the full ancestry, and the process is
frozen. There is no time limit on the stop, so the user can take as long as
necessary.

From that stop the monitor can:

* continue the process with `PTRACE_CONT`;
* end only the new program with `SIGKILL`, which means it never runs;
* end the whole session, children first.

The proof is a test that makes the target write a marker file as its first
action. After a deny, the marker file does not exist.

**What this boundary cannot do.** The `execve` of the old program already
succeeded. The firewall stops the *new program*, not the system call. So the
firewall protects against a dangerous **program**, and not against a dangerous
system call inside a program that already runs. A process that opens a file
and writes to it, with no new `execve`, is invisible at this level. That is
the honest limit of the first version, and it is the reason for the
`file_open_events` and `network_events` gaps above.
That was the state when this document was derived. A `seccomp` observation
layer now closes it; see `docs/DETECTION-RESEARCH.md` section 4, L1.

**A second surprise.** `PTRACE_O_TRACEEXIT` fires **even after `SIGKILL`** on
kernel 7.0. A monitor that kills a tracee and does not resume it waits for
ever in `waitpid`. The event loop therefore handles `PTRACE_EVENT_EXIT` before
it checks whether the session already ended, and every stop after a
termination goes through a "kill and continue" path.

*Test:* `af-monitor` `deny_stops_the_program_before_it_writes`,
`terminate_session_stops_the_whole_tree`; `af-cli`
`a_dangerous_command_is_stopped_and_recorded`.

---

## 6. Input inspection

**Question.** Where does a dangerous statement really appear for programs such
as `psql`, `mysql`, a shell, Python, Git, `kubectl` and `oc`?

| Place | Readable | Note |
| --- | --- | --- |
| `argv` | always | `psql -c "DROP DATABASE x"`, `git push --force` |
| A script file, for example `psql -f drop.sql` | always | the monitor reads the first 64 KiB |
| Standard input from a redirected file | yes | `psql < drop.sql` |
| A large here-document | yes | see below |
| A small here-document | no | see below |
| A pipe, for example `echo "..." \| psql` | no | nothing is stored |
| A socket | no | nothing is stored |
| Environment | yes | `PGHOST`, `DATABASE_URL` and similar names |

The important measurement concerns the here-document of a shell. Bash 5.3
backs a here-document with a **pipe** below about 64 KiB, and with a **deleted
temporary file** `/tmp/sh-thd.*` above it. Measured: 5 000 bytes gave a pipe,
65 536 bytes gave a temporary file.

When file descriptor 0 points to a regular file, the monitor opens the path
`/proc/<pid>/fd/0`. That open makes a **new file description with its own
offset**, so the monitor reads the content without taking one byte from the
tracee. A deleted file works in the same way, because the inode still lives.

A pipe and a socket hold no stored content, so the monitor skips them and says
so. To read them the firewall would have to stand between the two ends, which
means a system-call stop or a helper file descriptor. That work belongs to a
later version.

**What this means for policy design.** A rule that reads `argv` covers most of
the real risk today, because a coding agent almost always writes the dangerous
statement on the command line. A rule that reads content covers the script and
redirect cases. A rule must not depend on pipe content, because the firewall
cannot see it.

*Test:* `af-monitor` `stdin_snapshot_reads_a_redirected_file`,
`stdin_snapshot_skips_a_pipe`, `stdin_snapshot_reads_a_large_here_document`,
`script_snapshot_*`.

---

## 7. Findings that the plan did not ask for

**A wrapper script hides the tool.** Many real tools are shell scripts, for
example `npm` and `mvn`. When the kernel runs a script, `/proc/<pid>/exe`
points at the **interpreter**, so the program name is `bash` and not `npm`. A
rule that says `program: psql` then never matches.

The firewall answers this in `af-cli`: before it judges an exec, it looks for
the script file in the command line. When an interpreter runs a script that
exists, the judged program becomes the script. The recorded event always keeps
the true facts, so the provenance stays honest.

**A shell script must not be scanned for content.** The first version read the
text of every script and evaluated it. That gives a wrong answer twice: it
stops the shell before it reaches the command, and it reports a command that
the script can skip. Every command of a shell script becomes its own exec
event with its own provenance, so the exec event is the correct and the only
place to judge it. The firewall now scans content only for a program that is
not a shell, for example `python` or a database client.

---

## 8. Summary

| Research question | Answer |
| --- | --- |
| Observe the process tree without root | yes |
| Track every descendant with no race | yes |
| Launch or attach | launch |
| Read argv, exe, cwd, environment | yes |
| Hold a program before it runs | yes |
| End one program or the whole session | yes |
| Read argv and script content | yes |
| Read a redirected or large here-document | yes |
| Read a pipe or a socket | no |
| Observe file and network events | no, needs a privileged source |

The core hypothesis of PROJECT.md holds. A local, deterministic, user-space
monitor can reconstruct the full provenance of an action and can stop a
dangerous program before it runs, with no kernel module and no root.
