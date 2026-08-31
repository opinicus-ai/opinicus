# Threat research ledger

The ledger lists every incident and every scenario that the threat research
found, and how well the firewall covers them.

Sections:

- Headline numbers: the state in one table.
- Observable summary: how many scenarios the monitor of this version can see
  at all. This number decides the engineering roadmap.
- Coverage summary: what each policy pack must still answer.
- The interruption budget: why a scenario is not a rule.
- Incident ledger and Scenario ledger: the source material.
- Known blind spots and Run log.

Maintained by the workflow in `threat-research.workflow.js`. See `README.md`
for how to run it again.

## Headline numbers

| item | count |
| --- | ---: |
| incident reports in `incidents/` | 90 |
| scenarios in `scenarios/` | 255 |
| scenarios whose only needed observable is `exec`/`input` | **169** |
| scenarios that need `file_open` or `network_connect` — both shipped since the seccomp layer | **86** |

## Observable summary

A scenario is only useful when the monitor can produce the event that its
signal needs. Refreshed 2026-08-31, after the `seccomp` filter and the
M1–M7 ladder shipped: the monitor now emits `exec`, `input`, `file_open` and
`network_connect`, the Landlock floor answers the always-no rules in the
kernel, tamper and correlation events exist, and the research in-process
sensor adds `file_read`, `file_delete`, `file_rename`, `library_load` and
`env_change` when it is active. The split below is therefore no longer a
blocker count — it says which shipped observable a scenario's signal needs.

| the signal needs | scenarios | state |
| --- | ---: | --- |
| `exec` or `input` only | 169 | visible since the first version |
| `file_open` or `network_connect` | 86 | visible since the seccomp layer |

Every catalogue scenario's needed observable is produced by the shipped
monitor today. The actionable frontier is rules, not observables — the
honest blind spots that remain are in "Known blind spots" below.

## Coverage summary

`file/net` counts the scenarios of that pack whose signal needs the
`file_open`/`network_connect` observables. Both ship today, so the column is
coverage-planning input, not a blocker count.

| policy pack | gap | partial | file/net | actionable now |
| --- | ---: | ---: | ---: | ---: |
| cross (spans packs) | 54 | 13 | 33 | 34 |
| process | 53 | 6 | 13 | 46 |
| filesystem | 29 | 11 | 21 | 19 |
| network | 29 | 2 | 10 | 21 |
| cloud | 20 | 3 | 4 | 19 |
| git | 18 | 6 | 4 | 20 |
| database | 7 | 1 | 1 | 7 |
| mcp | 1 | 0 | 0 | 1 |
| **total** | **211** | **42** | **86** | **167** |

## The interruption budget

The scenarios propose a decision for each behaviour. Taken literally, the 77
actionable scenarios would add 76 rules that stop the user.

| | rules that stop the user | rules that only report |
| --- | ---: | ---: |
| the pack today | 41 | 28 |
| if every scenario is adopted as proposed | 122 | 29 |

`docs/PRODUCT.md` section 5 states that too many questions kill the product. A
user who is asked too often switches the protection off, and then the
protection is zero. **A scenario is not a rule.** Each scenario author saw one
threat alone, and nobody costed the total.

The rule for spending the budget:

> A rule may stop the user only when the outcome cannot be undone **and** the
> signal cannot fire on a normal development command. The second half must be
> proved by a negative test in the rule itself. Everything else becomes
> `risk: suspicious` with `decision: allow`, which records and explains the
> event at no cost to the user.

## Incident ledger

90 reports in `incidents/`, named `<axis>-<slug>.md`. Each one holds the
facts, the sources and the lesson for the policy pack.

| axis | reports |
| --- | ---: |
| supply | 14 |
| inject | 11 |
| behavior | 9 |
| mcp | 9 |
| exfil | 9 |
| secrets | 9 |
| evade | 8 |
| vcs | 8 |
| cloud | 7 |
| fs | 6 |

## Scenario ledger

254 scenarios in `scenarios/<axis>.md`. Every scenario holds a behaviour, an
example, a signal written only in observables the monitor has, a decision, a
severity and a coverage state.

| axis | scenarios | gap | partial | needs file/net |
| --- | ---: | ---: | ---: | ---: |
| behavior | 26 | 19 | 7 | 8 |
| cloud | 28 | 25 | 3 | 7 |
| evade | 25 | 20 | 4 | 9 |
| exfil | 26 | 24 | 2 | 13 |
| fs | 23 | 16 | 7 | 4 |
| inject | 23 | 19 | 4 | 11 |
| mcp | 24 | 22 | 2 | 6 |
| secrets | 25 | 24 | 1 | 13 |
| supply | 28 | 25 | 3 | 7 |
| vcs | 27 | 17 | 9 | 8 |

`exfil` and `secrets` are the axes that lean hardest on the file and network
observables (13 of 26 scenarios in exfil, 13 of 25 in secrets). Those observables ship today, so
these axes are now the natural home of new chain rules — the firewall no
longer has to be weak on data that leaves the machine.

## Known blind spots

Behaviour that no observable of any planned layer reports.

| behaviour | why it is invisible |
| --- | --- |
| `io_uring` batch input and output | The operations run inside one `io_uring_enter` call, so no per-operation system call happens and both boundaries and the sensor record nothing. Measured live: `research/bypass/FINDINGS.md` gap 1 (`evade-15`). |
| Content in a pipe or a socket | Nothing is stored, so there is nothing to read. Measured in `docs/RESEARCH.md` section 6. |
| Content capture keyed on interpreter names | `/usr/bin/python3` is a symlink to `python3.14`, which is in no interpreter list, so the script snapshot never fires for Python on this machine. The research sensor sees it (pydrop, `research/bypass/FINDINGS.md`); the shipped capture does not yet. |

## Run log

| date | incidents | scenarios | notes |
| --- | --- | --- | --- |
| 2026-08 | 57 added | 147 added | first research run, ten axes |
| 2026-08 | — | — | ledger rebuilt from the files on disk; observable and interruption-budget analysis added |
| 2026-08 | 18 added | 52 added | rerun added 18 incident reports and 52 scenarios; no axis failed |
| 2026-08 | 1 added | 1 added | manual add: Simon Brook LinkedIn report, Auto Mode `$HOME` drift home wipe; distinct from the 2025-12 `rm -rf ~/` twin |
| 2026-08 | 13 added | 49 added | rerun added 13 incident reports and 49 scenarios; no axis failed |
| 2026-08 | 1 added | 1 added | manual add: evade-25 evidence erasure (the session rewrites its own transcript, the shell history, and the firewall's trace); follow-up to the bypass-harness and deep-dive findings |
| 2026-08 | 1 added | 5 added | deep dive: the July 2026 OpenAI agent-swarm intrusion into Hugging Face folded in as one report and 5 scenarios |
