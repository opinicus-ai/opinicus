# Agent Firewall

A local security layer for coding agents. It watches what an agent really
does, and it stops a dangerous action before the action runs.

Status: proof of concept for Linux. Read [the limits](#what-works-and-what-does-not)
before you use it.

## The problem

A coding agent runs shell commands on your machine. The agent writes a
script, the script starts a second script, and the second script starts a
database client. A sandbox stops too much, because the agent then cannot do
its work. A prompt for each command stops too little, because the prompt
shows one command without its history. Nobody sees that the innocent command
`bash ./migrate.sh` ends in `DROP DATABASE customer_prod`.

## What the product does

The Agent Firewall starts the coding agent and follows every child process
of that agent. It converts the process events into one normalized event
stream, builds the chain from the agent to the acting process, and matches
deterministic rules against the action. It holds a dangerous action at the
exec boundary, shows the chain and the rule that matched, and lets you allow
or deny the action.

The firewall needs no model, no network and no root account.

## The demonstration

```console
$ demo/run-demo.sh

Scenario B — the firewall stops the dangerous action
The process chain is:
  agent-firewall -> agent-sim.sh -> bash -> migrate.sh -> psql
$ agent-firewall run --approve deny --trace trace-b.jsonl --print-tree -- bash ./agent-sim.sh

[agent] test the database connection
statement: SELECT 1
result: accepted by the demo client (no server, no data changed)

[agent] run the migration script
migrate: step 1 of 5 — test the connection
migrate: step 2 of 5 — read the schema version
migrate: step 3 of 5 — create the new table
migrate: step 4 of 5 — copy the old rows
migrate: step 5 of 5 — remove the old database

bash ./agent-sim.sh [pid 41201]
  -> bash -c cd … && bash ./migrate.sh [pid 41230]
    -> bash ./migrate.sh [pid 41231]
      -> psql -h db.prod.internal -U app -d customer_prod -c DROP DATA… [pid 41244]
Attempted operation:
  psql -h db.prod.internal -U app -d customer_prod -c DROP DATABASE customer_prod
Policy:
  database.destructive.drop-database — a statement drops a whole database
Reason:
  the command line of psql holds DROP DATABASE
Risk:
  approval-required
Decision:
  deny

exit code:                     3 (expected 3)
DROP DATABASE in marker file:  0 (expected 0)
marker file: tmp/demo/marker-b.txt
  EXECUTED: SELECT 1
  EXECUTED: SELECT version FROM schema_version ORDER BY version DESC LIMIT 1
  EXECUTED: CREATE TABLE IF NOT EXISTS customer_archive ( … )
  EXECUTED: INSERT INTO customer_archive (id, name) SELECT id, name FROM customer …

Result
ID  Scenario                               Expected                           Result
--  --------                               --------                           ------
A   normal work                            exit 0, no question                PASS
B   dangerous action, deny                 exit 3, no DROP DATABASE line      PASS
C   dangerous action, allow                DROP DATABASE line present         PASS
```

The demonstration touches no database. The program `demo/bin/psql` is a fake
client. It only prints. It appends one line `EXECUTED: <statement>` to a
marker file at the point where a real client sends the statement to a
server. The marker file above holds the four harmless statements, but it
holds no `DROP DATABASE` line. The dangerous program never started.

## Build

You need Linux, Rust 1.85 or later, `bash` and `git`.

```console
$ cargo build --release
```

The binary is `target/release/agent-firewall`.

## Run

Start a coding agent under the firewall:

```console
$ agent-firewall run --trace session.jsonl -- claude
```

Every descendant process of the agent stays part of the session. The
firewall writes its own text to standard error, so the output of the agent
stays clean on standard output.

| Command | Function |
| --- | --- |
| `run [OPTIONS] -- <command>` | Starts a command and watches the process tree. |
| `replay <TRACE>` | Evaluates a recorded trace again. |
| `tree <TRACE>` | Draws the process tree of a trace. |
| `policy list` | Lists every loaded rule. |
| `policy check <PATH>...` | Validates policy files. |
| `policy test` | Runs the tests inside the policy files. |
| `doctor` | Reports what the monitor can observe on this machine. |

Options of `run`:

| Option | Function |
| --- | --- |
| `--policy <PATH>` | Adds a policy file or directory. You can repeat it. |
| `--no-builtin-policies` | Does not load the rule pack inside the binary. |
| `--trace <PATH>` | Writes the normalized events as JSON Lines. |
| `--approve <MODE>` | `ask`, `allow` or `deny`. The default is `ask` on a terminal and `deny` without one. |
| `--approval-timeout <S>` | Denies when nobody answers in this many seconds. |
| `--syscall-filter <MODE>` | `write-only` (the default), `all-opens` or `off`. See below. |
| `--print-tree` | Prints the process tree when the session ends. |
| `--json` | Prints every event as JSON on standard output. |
| `-v`, `--verbose` | Prints every normalized event as text. |

### What the firewall sees inside a running program

A kernel filter holds the few system calls that a rule can judge, so the
firewall also sees what a program does **after** it started. The filter costs
a little time at every call it holds, and nothing at all at the other calls,
so the mode is a choice.

| `--syscall-filter` | What the firewall sees | Measured cost |
| --- | --- | --- |
| `write-only` (default) | a file open that can change the file, and every outgoing connection | 1.16× to 1.33× |
| `all-opens` | the same, and an open that only reads | 1.33× to 1.92× |
| `off` | nothing beyond a new program | no cost above the monitor itself |

Every number is measured against the `ptrace` monitor and not against a
session with no firewall. The monitor itself is the larger part of the price:
a file-heavy workload under `ptrace` alone was about ten times slower than the
same workload with no firewall. `off` adds nothing to that; it does not make
the session free.

The default is cheap because the kernel itself drops a read-only open, and a
read is 99.7% of the file traffic of a normal build. The price is that a rule
about the path of a **read** — a credential file that a program only reads —
cannot fire. Run `policy list` to see which rules that is, and
`--syscall-filter all-opens` to wake them.

`off` also gives the session back its right to raise privilege: the firewall
only asks the kernel for `no_new_privs` when it really installs a filter.
`ptrace` takes the setuid bit away in every mode, though, so `sudo` does not
work under the firewall whatever the mode is.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| exit code of the child | The child ended, and the firewall stopped nothing. |
| 3 | The firewall stopped the session. |
| 2 | Usage error. |

## Run the demonstration and the test

```console
$ demo/run-demo.sh          # builds the workspace and runs three scenarios
$ demo/run-demo.sh --no-build
$ tests/e2e.sh              # the end-to-end test for a person or for CI
```

Both scripts work from any directory. Both scripts use `demo/bin/psql`, so
no database can change. Both scripts make a throwaway git repository in
`tmp/`. The test removes its own files.

## State of the project

This repository holds a proof of concept. It answers one question: can a
program in user space stop a dangerous action inside a deep process chain,
without a kernel module and without root? The answer on Linux is yes, at the
exec boundary and at a small set of system calls.

### What works and what does not

Works today:

* the firewall starts a command and follows every descendant process;
* the monitor sees `fork`, `clone`, `exec` and `exit` of every descendant;
* the monitor reads the program path, the command line and the working
  directory of a new program;
* the provenance engine builds the chain from the session root to the acting
  process;
* the policy engine matches deterministic rules against the program name,
  the arguments and the ancestry;
* the firewall holds the process before the new program starts, and it asks
  the user;
* a kernel filter holds a file open that can change the file, and every
  outgoing connection, **inside a program that already runs**; the firewall
  reports it, asks about it, and can let the call fail with a permission
  error while the program keeps running;
* the recorder writes a trace, and `replay` evaluates the trace again,
  including the file and the network actions. The default trace keeps every
  file and network action that a rule matched, so a chain that the live
  session found is found again in the replay; an action that no rule matched
  is dropped, and it could not change a verdict.

Does not work yet:

* Linux only. macOS and Windows need another collector.
* The kernel filter is `x86_64` only. On another architecture the firewall
  says so and keeps the exec boundary alone. A **32-bit program on an
  `x86_64` machine** is the same gap one level down: it uses another table of
  system-call numbers, so the filter lets its calls through rather than
  reading them wrongly. The firewall still holds every new program of such a
  process, and it writes a warning at the start of it, so the gap is visible
  in the session and in the trace.
* No content of an open connection. The firewall sees that a program
  connects, and not the statement that the program sends over a connection
  that is already open. Watching that costs 8.8× and is not worth it.
* No delete and no rename event. The schema has no shape for them yet, so a
  delete is still judged at the command that does it.
* A path that a rule reads is **not proof**. The firewall reads it out of
  the memory of the program that it judges, and a second thread of that
  program can change it in the meantime. It is good enough to report, to
  refuse and to ask, and it is never the reason to allow something.
* No inspection of standard input. A statement that a program reads from a
  pipe after its start stays invisible. The demonstration therefore puts the
  dangerous statement in the command line.
* No agent log adapters. The firewall knows the process tree, but it does
  not know the tool call of the agent.
* The firewall cannot be restarted under a live session. A traced call
  returns "Function not implemented" while no firewall is there, so the
  program breaks rather than going unobserved.
* The monitor uses `ptrace`. A traced process runs slower, and the kernel
  ignores the setuid bit of a new program, so `sudo` cannot raise privilege.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full boundary.

## Workspace layout

| Path | Function |
| --- | --- |
| `crates/af-core` | The shared contract: normalized events, process facts, decisions and the traits between the layers. |
| `crates/af-monitor` | The Linux collector. It starts a command under `ptrace`, follows every descendant, holds a process at the exec boundary, and holds a chosen system call with a `seccomp` filter. |
| `crates/af-provenance` | The provenance graph. It answers which process started which process. |
| `crates/af-policy` | The deterministic policy engine, the rule format and the rule pack inside the binary. |
| `crates/af-approval` | The approval layer. It asks the user on the terminal and remembers a session decision. |
| `crates/af-recorder` | The trace writer and the trace reader for JSON Lines. |
| `crates/af-cli` | The `agent-firewall` command. It connects all layers. |
| `policies/` | Policy files in the readable source format. |
| `demo/` | The demonstration: a fake `psql`, a dangerous migration script and an agent simulator. |
| `tests/e2e.sh` | The end-to-end test. |

## Documents

* [PROJECT.md](PROJECT.md) — the idea, the principles and the plan.
* [docs/PRODUCT.md](docs/PRODUCT.md) — the problem, why the constraints are
  not optional, and what kills the product.
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the layers, the path of one
  exec and the enforcement boundary.
* [docs/POLICY.md](docs/POLICY.md) — the rule format and the rule pack.
* [docs/RESEARCH.md](docs/RESEARCH.md) — the Linux research questions of
  PROJECT.md section 10 with measured answers, and the limits they show.
* [docs/DETECTION-RESEARCH.md](docs/DETECTION-RESEARCH.md) — which mechanism
  the firewall should watch with, measured across four spikes, and the
  layered recommendation that follows.
* [docs/DETECTION-REQUIREMENTS.md](docs/DETECTION-REQUIREMENTS.md) — what the
  firewall must observe and remember before the known attack vectors can be
  expressed, derived from 147 threat scenarios.
* [research/threats/](research/threats/) — the threat research ledger: real
  coding-agent failure incidents and the block scenarios they justify, kept
  by a reusable research workflow.

## Licence

Apache License 2.0. Read [LICENSE](LICENSE).
