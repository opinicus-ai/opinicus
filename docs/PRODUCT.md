# The product idea

`PROJECT.md` says what to build. This document says **why**, and which
decisions are not free choices.

---

## 1. The problem

A coding agent must run commands to be useful. Two answers exist today, and
both fail.

| Answer | How it fails |
| --- | --- |
| A strict sandbox | A sandbox that is strict enough to be safe makes the agent useless. |
| A per-command approval prompt | The prompt asks about `bash migrate.sh`. It shows nothing about the `DROP DATABASE` four processes below. The user clicks "yes" with no information. |

The gap between these two answers is where the damage happens. Nobody watches
what the child processes of the agent really do.

---

## 2. The insight

Do not guess what the agent **wants**. Watch what it **does**, at the
operating-system boundary, where the truth is. Then keep the causal chain, so
a decision can be explained.

This is why the product is independent of the agent. It watches effects, and
not the agent. Codex, Claude Code, Gemini CLI and every future agent all make
processes, and a process is visible.

---

## 3. Why the constraints are not optional

**Local enforcement.** A security control that needs a network call has the
failure modes that a security control must not have. It must protect the user
when the network is down.

**Deterministic decisions.** A model that decides allow or deny gives a
different answer to the same input. A user cannot trust that, and an auditor
cannot accept it. A model can explain and suggest. It must not decide.

**User space.** A product that needs root will not be installed. Low friction
is a security feature, because protection that nobody installs protects
nobody. This is the law of the developer edition. The enterprise edition may
later add privileged, policy-enforced components — under the principle that
*an AI-controlled process must not continue if security visibility is lost* —
but nothing in the developer edition may require root
([DIRECTION.md](DIRECTION.md) §10).

---

## 4. What the business really is

The runtime is the distribution channel. The value is the maintained rule
feed.

The shape is the same as antivirus signatures, but the rules describe
**behaviour** instead of file hashes: a process chain, arguments, a
destination, a statement, and the provenance of all of it.

This is why "collect real agent incidents and turn them into regression tests"
is a business activity, and not only an engineering activity. Each new
incident becomes a rule, a test, and a reason to keep the subscription.

---

## 5. What kills the product

Not a missed attack. **Too many questions.**

A user who is asked too often switches the protection off. Then the protection
is zero, and the missed attack does not matter any more.

So the rule pack is deliberately unbalanced — 161 rules, counted with
`agent-firewall policy list --json` and classified by
`research/spikes/landlock/tests/count-rules.py` (the io_uring report of
[af-12] is the newest):

| Behaviour | Rules |
| --- | --- |
| Stop the action and ask, or block it | 77 |
| Report only, and stay quiet | 84 |

Six of the questions are not asked at all any more: the Landlock kernel
floor answers them in the kernel, before the program starts, with no
supervisor in the loop and at a measured cost of 0.98×–1.07× on the bench
workloads — no cost within the noise of the measurement
(`research/spikes/landlock/FINDINGS.md`; `research/bench/floor.sh` measures
the product with the floor on and off and shows the same). Quiet by
construction is the cheapest quiet there is.

Only an operation that destroys data or infrastructure with no simple way back
may stop the user. A `kubectl delete pod`, a `git branch -D` and a
`docker rm -f` are recoverable, so they only report.

The demonstration must show normal work passing in silence. **Quiet is the
feature.**

---

## 6. The open question

The question this document used to ask — *is the exec boundary enough in
practice?* — was answered: no, and the answer shipped. A single Python
process deleted a tree, deleted a file and opened a connection while the
firewall denied everything, because no new program started. The `seccomp`
filter of [ARCHITECTURE.md](ARCHITECTURE.md) §3a now holds the file opens and
the connections inside a running program, at about 1.2× cost
([DETECTION-RESEARCH.md](DETECTION-RESEARCH.md) §4).

The open questions are now the ten of [DIRECTION.md](DIRECTION.md) §11. The
one this document weighs in on most directly is the ninth: **how much context
distinguishes legitimate coding behavior from dangerous behavior?** Session
memory is the answer so far — the chain of two actions, the burst, the
baseline — and the interruption budget above is the test every new context
rule has to pass.

The wider direction changes one thing about this document's frame: a sensor
is not a boundary. In-process instrumentation will report what a program is
about to do, the external sensors will report what it actually did, and a
discrepancy between the two is itself a high-severity signal
([DIRECTION.md](DIRECTION.md) §3.4).
