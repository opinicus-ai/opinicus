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
| incident reports in `incidents/` | 76 |
| scenarios in `scenarios/` | 200 |
| scenarios whose only needed observable is `exec`/`input` | **126** |
| scenarios that need `file_open` or `network_connect` — both shipped since the seccomp layer | **74** |

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
| `exec` or `input` only | 126 | visible since the first version |
| `file_open` or `network_connect` | 74 | visible since the seccomp layer |

Every catalogue scenario's needed observable is produced by the shipped
monitor today. The actionable frontier is rules, not observables — the
honest blind spots that remain are in "Known blind spots" below.

## Coverage summary

`file/net` counts the scenarios of that pack whose signal needs the
`file_open`/`network_connect` observables. Both ship today, so the column is
coverage-planning input, not a blocker count.

| policy pack | gap | partial | file/net | actionable now |
| --- | ---: | ---: | ---: | ---: |
| cross (spans packs) | 45 | 13 | 29 | 29 |
| process | 47 | 5 | 13 | 39 |
| filesystem | 22 | 9 | 16 | 15 |
| network | 21 | 2 | 8 | 15 |
| cloud | 15 | 2 | 4 | 13 |
| git | 9 | 4 | 3 | 10 |
| database | 3 | 1 | 1 | 3 |
| mcp | 1 | 0 | 0 | 1 |
| **total** | **163** | **36** | **74** | **125** |

## The interruption budget

The scenarios propose a decision for each behaviour. Taken literally, the 77
actionable scenarios would add 76 rules that stop the user.

| | rules that stop the user | rules that only report |
| --- | ---: | ---: |
| the pack today | 41 | 28 |
| if every scenario is adopted as proposed | 117 | 29 |

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

75 reports in `incidents/`, named `<axis>-<slug>.md`. Each one holds the
facts, the sources and the lesson for the policy pack.

| axis | reports |
| --- | ---: |
| supply | 11 |
| inject | 9 |
| behavior | 9 |
| mcp | 8 |
| evade | 7 |
| exfil | 7 |
| secrets | 7 |
| vcs | 7 |
| cloud | 6 |
| fs | 5 |

## Scenario ledger

199 scenarios in `scenarios/<axis>.md`. Every scenario holds a behaviour, an
example, a signal written only in observables the monitor has, a decision, a
severity and a coverage state.

| axis | scenarios | gap | partial | needs file/net |
| --- | ---: | ---: | ---: | ---: |
| behavior | 20 | 14 | 6 | 5 |
| cloud | 21 | 18 | 3 | 7 |
| evade | 21 | 17 | 4 | 7 |
| exfil | 20 | 18 | 2 | 12 |
| fs | 19 | 13 | 6 | 4 |
| inject | 19 | 16 | 3 | 10 |
| mcp | 20 | 18 | 2 | 5 |
| secrets | 20 | 19 | 1 | 12 |
| supply | 19 | 17 | 2 | 4 |
| vcs | 21 | 13 | 7 | 8 |

`exfil` and `secrets` are the axes that lean hardest on the file and network
observables (12 of 20 scenarios in each). Those observables ship today, so
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
