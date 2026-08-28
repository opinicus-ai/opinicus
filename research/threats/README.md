# Threat research

Research that answers one question: **what can a coding agent do that the
firewall must block, gate, or at least see?**

Everything here feeds the policy packs in `policies/` and the rule tests in
`docs/POLICY.md`. The flow is:

```
web research  ->  incident reports (incidents/)  ->  ledger (LEDGER.md)
                                                        |
                                          scenarios with coverage gap
                                                        |
                                          new rules in policies/ + tests
```

## Directory

| path | what it is |
| --- | --- |
| `LEDGER.md` | the single source of truth: every incident (INC-###) and every scenario (SC-###) with ids, status, and coverage |
| `incidents/` | one report per real-world failure of a coding agent or its toolchain, named `<axis>-<slug>.md` |
| `threat-research.workflow.js` | the reusable multi-agent research workflow (script for the pi `workflow` tool, not runnable directly) |

## Research axes

| code | axis |
| --- | --- |
| `fs` | filesystem destruction and data loss |
| `vcs` | git and version-control damage |
| `secrets` | secret and credential harvesting |
| `exfil` | network exfiltration and unauthorized egress |
| `supply` | supply chain, malicious packages, install scripts |
| `inject` | prompt injection that turns into real actions |
| `cloud` | production infra, databases, CI/CD |
| `mcp` | MCP servers and tool/plugin ecosystem |
| `behavior` | agent self-inflicted failures (loops, self-modification, wrong targets) |
| `evade` | monitor evasion and OS-level tricks (red-team axis) |

Edit the `AXES` list in `threat-research.workflow.js` to add or remove axes.

## How to run it again

Ask the agent to **"run the threat research workflow"** (or
`/skill:threat-research`). The steps, done by the agent:

1. Read this directory: `LEDGER.md` and `threat-research.workflow.js`.
2. Call the pi `workflow` tool with:
   - `script`: the full content of `threat-research.workflow.js`
   - `args`: JSON `{"ledger": "<full content of LEDGER.md>"}`
   - `background: true`
3. When the run settles: check `git status`, spot-check the new incident
   reports, and summarize what the ledger gained.
4. Follow up on `coverage: gap` scenarios by writing policy rules and tests.

Every run deduplicates against the ledger passed in `args`, so it is safe to
run as often as wanted. The merge step is the only writer of `LEDGER.md`.

## Scenario lifecycle

| status | meaning |
| --- | --- |
| `proposed` | found by research, no rule yet |
| `rule-written` | a rule id in `policies/` claims the scenario (put the id in the sources column) |
| `tested` | the rule has tests in its yaml that prove the scenario |

Goal of the program: no `gap` scenarios left, every scenario `tested`.
