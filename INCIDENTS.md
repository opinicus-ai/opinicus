# When a session was stopped: the incident guide

This page is for the operator who just watched `agent-firewall` exit with a
code they did not expect, or a user whose normal work was interrupted. It
answers, in order: **what happened**, **what actually ran**, **where the
evidence is**, and **what to do next**.

The whole page assumes the alpha contract
([README.md](README.md), *The alpha*): false positives are expected bugs,
false negatives are possible, and the firewall must never be your only
protection. A stopped session is an event to investigate, not a verdict
about a person.

## The exit codes

`run --help` prints the same table; `run --summary <PATH>` writes the code
into a machine-readable session summary when one was requested.

| Code | Meaning |
| --- | --- |
| `0` | The session ended, and the firewall stopped nothing. |
| `3` | The firewall stopped an action (a rule denial, a refusal or a ruling); the session did not run to its end. |
| `2` | The firewall could not run the session at all (an unknown option, a policy that cannot load, a monitor failure). |
| `N` | The program of the session exited with code `N`, when the session ran to its end (for example `7` after `exit 7`). |
| `128+N` | The program of the session died of signal `N`. |

## Exit 3 — was anything executed?

The precise answer has three parts.

**The held action never ran.** The firewall judges at real boundaries, and a
denial happens on the near side of the boundary:

* A **new program** is judged at the `execve` stop: the kernel stops the
  process at the entry of the system call, *before the first instruction of
  the new program* ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3,
  steps 2 and 9). A deny writes an invalid call number into the stopped
  process, so the `execve` fails and the program **never starts** — no
  instruction of it ran. The caller (the shell that invoked it) continues
  and sees an ordinary error.
* A **file open or a connection** is judged at the system-call stop of a
  running program: the call has **not happened** when the question is asked
  — no byte is written and no packet has left
  ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3a). A deny makes the call
  fail with `EACCES`/`EPERM`; the program sees a permission error in its own
  words.

**Everything before the stop ran.** Exit 3 names the moment of the stop, not
the whole session. Every action the session completed *before* the held
action — files written, connections made, commands that ran — really
happened, and a denial cannot undo any of it. What ran is in the evidence
below; read it before you say "it never executed".

**A terminate is stronger than a deny and still not time travel.** A rule
with `decision: terminate`, a `t` answer at a prompt, or a terminate ruling
in a quarantine kills the process tree of the session. Actions already
completed before the kill stay completed.

Honest limits of the same answer: the guarantee holds where the boundary
holds. `agent-firewall doctor` tells you whether this machine can hold a
program at the exec stop at all; with `--syscall-filter off` only new
programs are held (a running program's file and network calls are not
judged); and the measured gaps of the alpha — the limits of ptrace, the
advisory layers, the known bypasses — are part of the product in
[README.md](README.md) (*What works and what does not*) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Where the evidence is

Every session leaves up to three records:

1. **The trace** (`--trace <PATH>`, JSON Lines) — the machine's memory of
   the session, one event per line. This is the record a replay evaluates
   and a false-positive report is built from.
2. **The session log** — a plain-text log every `run` writes, whether or
   not `--trace` was given:
   `${XDG_STATE_HOME:-$HOME/.local/state}/agent-firewall/sessions/<session
   id>.log`, created with mode `0600` because it holds command lines and
   paths. The CLI prints the path when the session ends.
3. **The terminal** — the explanation of the held action at the moment of
   the question, and, when a session ends with any intervention, the
   plain-text block *what ran, what was stopped, what to do now* (rule ids,
   the exact replay command, the report command).

### How to read the session log

One line per support-relevant event, oldest first, every line with a UTC
ISO-8601 time stamp:

```text
2026-09-01T12:00:00.123Z session afw-1a2b3c started: bash ./agent-sim.sh (cwd /work) agent=claude-code (0.95)
2026-09-01T12:00:01.456Z decision approval-required rule=database.destructive.drop-database: psql -c DROP DATABASE customer_prod (pid 401)
2026-09-01T12:00:01.456Z question rule=database.destructive.drop-database: psql -c DROP DATABASE customer_prod (pid 401)
2026-09-01T12:00:03.789Z answer rule=database.destructive.drop-database: deny after 2331ms
2026-09-01T12:00:03.790Z quarantine rule=tamper.quarantine: signal 9 to process 900 — Signal the firewall (pid 402)
2026-09-01T12:00:04.100Z quarantine resolved rule=tamper.quarantine: terminate
2026-09-01T12:00:04.200Z session afw-1a2b3c ended: exit=3 processes=5
```

The kinds of line: `started` and `ended` (the frame), `decision` (one per
policy decision that was not a plain allow — always with the rule id),
`question` / `answer` (what the firewall asked and what was answered),
`quarantine` / `quarantine resolved`, `tamper`, `unlinked` (a process left
the session tree), `kernel denied` (the Landlock floor refused an open),
`warning`. A session nothing stopped writes only its frame — the
interruption budget ([docs/PRODUCT.md](docs/PRODUCT.md) §5) holds for the
log too.

## How to replay the evidence

The trace is deterministic evidence: a replay evaluates the same events
under the rules and reaches the same verdicts, because the engine reads
only what the trace carries (the session memory travels inside the events).

```console
$ agent-firewall replay trace.jsonl                 # with the built-in pack
$ agent-firewall replay trace.jsonl --policy my-rules.yaml
$ agent-firewall tree trace.jsonl                   # who ran under whom
```

The session-end block prints the exact replay command of that session —
including the `--policy` flags it ran with, so the replay sees the same
rules the live session saw.

## How to report a false positive

A false positive is **a normal action that was questioned, refused or
stopped**, where the session was doing ordinary work. Quiet is the feature:
a rule that cannot prove a quiet negative does not ship
([docs/POLICY.md](docs/POLICY.md) §6), so every case of noise is a real
bug.

1. **Build the report bundle** — never attach a raw trace; it holds command
   lines, paths and environment values:

   ```console
   $ agent-firewall report trace.jsonl
   report: agent-firewall-report-s-3f9c2d81ab01.json
   ```

   The command validates the trace, then redacts it with the same machinery
   as the telemetry samples: assignments with secret-shaped names and
   known-prefix credentials (`ghp_…`, `sk-…`, `AKIA…`) become
   `<redacted>`, environment values never travel (names stay), observed
   content is `<omitted>`, and the session, process, home, login and host
   identifiers are pseudonymized. The file is written locally with mode
   `0600` and **nothing is sent anywhere** — read it before you post it.

2. **Open the issue** with the template
   [`.github/ISSUE_TEMPLATE/false-positive.md`](.github/ISSUE_TEMPLATE/false-positive.md)
   and attach the bundle. Name the rule id — it is in the prompt text, in
   the session log (`rule=…`), and in the report.

A false negative — something dangerous that was not stopped — goes through
[SECURITY.md](SECURITY.md) and the false-negative template instead.

## The operational checklist, in one block

```text
exit 3?
  1. What was stopped?  → the session-end block on the terminal, or the log:
                          ~/.local/state/agent-firewall/sessions/<id>.log
  2. What ran before?   → agent-firewall tree trace.jsonl
  3. Was it right?      → agent-firewall replay trace.jsonl (same rules, same answer)
  4. Wrong?             → agent-firewall report trace.jsonl
                          + .github/ISSUE_TEMPLATE/false-positive.md
```
