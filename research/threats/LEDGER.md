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
| incident reports in `incidents/` | 57 |
| scenarios in `scenarios/` | 147 |
| scenarios the monitor can see today (`exec` or `input` only) | **77** |
| scenarios that need an observable the monitor does not make | **70** |

## Observable summary

A scenario is only useful when the monitor can produce the event that its
signal needs. This version makes two action kinds, `exec` and `input`. It does
not make `file_open` or `network_connect`.

| the signal needs | scenarios | state |
| --- | ---: | --- |
| `exec` or `input` only | 77 | can become a rule now |
| `file_open` or `network_connect` | 70 | blocked on the monitor |

**48 percent of the threat catalogue cannot be expressed today.** This is
independent evidence for the layer 1 work that `docs/DETECTION-RESEARCH.md`
recommends: `seccomp RET_TRACE` adds exactly these two observables for about
1.2 times the cost.

Seven rules in `policies/` were already written against the missing
observables, so they can never fire. `agent-firewall policy list` marks them
`(inactive)` and names them.

## Coverage summary

`blocked` counts the scenarios of that pack that need an observable the
monitor does not make.

| policy pack | gap | partial | blocked | actionable now |
| --- | ---: | ---: | ---: | ---: |
| cross (spans packs) | 35 | 10 | 28 | 17 |
| process | 29 | 5 | 12 | 22 |
| filesystem | 18 | 7 | 15 | 10 |
| network | 17 | 2 | 8 | 11 |
| cloud | 9 | 2 | 4 | 7 |
| git | 5 | 4 | 2 | 7 |
| database | 2 | 1 | 1 | 2 |
| mcp | 1 | 0 | 0 | 1 |
| **total** | **116** | **31** | **70** | **77** |

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

57 reports in `incidents/`, named `<axis>-<slug>.md`. Each one holds the
facts, the sources and the lesson for the policy pack.

| axis | reports |
| --- | ---: |
| supply | 9 |
| inject | 7 |
| behavior | 6 |
| mcp | 6 |
| cloud | 5 |
| evade | 5 |
| exfil | 5 |
| secrets | 5 |
| vcs | 5 |
| fs | 4 |

## Scenario ledger

147 scenarios in `scenarios/<axis>.md`. Every scenario holds a behaviour, an
example, a signal written only in observables the monitor has, a decision, a
severity and a coverage state.

| axis | scenarios | gap | partial | blocked on an observable |
| --- | ---: | ---: | ---: | ---: |
| behavior | 14 | 9 | 5 | 5 |
| cloud | 15 | 12 | 3 | 7 |
| evade | 15 | 12 | 3 | 6 |
| exfil | 15 | 14 | 1 | 12 |
| fs | 15 | 10 | 5 | 4 |
| inject | 15 | 12 | 3 | 9 |
| mcp | 15 | 13 | 2 | 5 |
| secrets | 15 | 14 | 1 | 12 |
| supply | 13 | 11 | 2 | 3 |
| vcs | 15 | 9 | 6 | 7 |

`exfil` and `secrets` are the most blocked axes: 12 of 15 scenarios in each
need an observable that the monitor does not make. That is why the firewall
today is strong on a destructive command and weak on data that leaves the
machine.

## Known blind spots

Behaviour that no observable of any planned layer reports.

| behaviour | why it is invisible |
| --- | --- |
| `io_uring` batch input and output | The operations make no system call that a per-call monitor sees. Named in `scenarios/evade.md`. |
| An action inside a running program | No new program starts, so no exec stop happens. Layer 1 closes the file and network part of this. |
| Content in a pipe or a socket | Nothing is stored, so there is nothing to read. Measured in `docs/RESEARCH.md` section 6. |

## Run log

| date | incidents | scenarios | notes |
| --- | --- | --- | --- |
| 2026-08 | 57 added | 147 added | first research run, ten axes |
| 2026-08 | — | — | ledger rebuilt from the files on disk; observable and interruption-budget analysis added |
