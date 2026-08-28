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
nobody.

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

So the rule pack is deliberately unbalanced:

| Behaviour | Rules |
| --- | --- |
| Stop the action and ask, or block it | 41 |
| Report only, and stay quiet | 28 |

Only an operation that destroys data or infrastructure with no simple way back
may stop the user. A `kubectl delete pod`, a `git branch -D` and a
`docker rm -f` are recoverable, so they only report.

The demonstration must show normal work passing in silence. **Quiet is the
feature.**

---

## 6. The open question

Test whether the exec boundary is enough in practice, before you build more on
it.

The firewall stops a dangerous **program**. It does not stop a dangerous write
inside a program that already runs.

* `psql -c "DROP DATABASE customer_prod"` — caught. A new program starts.
* A Python script that deletes rows through a database library — not caught.
  No new program starts.

The answer decides the next investment:

1. `PTRACE_SYSCALL` filtering — full visibility, but it stops the process twice
   for every system call;
2. an eBPF or `fanotify` path — low cost, but it needs privileges;
3. more rules on the present boundary — cheap, and it accepts the limit.

`docs/RESEARCH.md` holds the measurements that this question needs.
