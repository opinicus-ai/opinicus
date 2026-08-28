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
| `LEDGER.md` | the analysis document: headline numbers, observable summary, coverage summary, the interruption budget, per-axis tables, run log. Updated in place by each run; the prose is preserved |
| `incidents/` | the incident source of truth: one report per real-world failure, named `<axis>-<slug>.md` |
| `scenarios/` | the scenario source of truth: one catalog per axis, `<axis>.md`, with numbered sections `### SC <axis>-NN <title>` |
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
   - `args`: JSON with the current state:
     - `ledger`: full content of `LEDGER.md`
     - `knownReports`: list of `{f, t}` (filename, title) for every report
       already in `incidents/`, so no incident is researched twice
   - `background: true`
3. When the run settles: check `git status`, spot-check the new incident
   reports, and summarize what the ledger gained.
4. Follow up on `coverage: gap` scenarios by writing policy rules and tests.

Every run deduplicates against what is on disk: researchers read their axis
catalog first and append only new numbered sections, and incidents dedupe
against `knownReports`. The merge step edits only the ledger's count tables
and appends a run log row; analysis prose is never rewritten.

A few incidents were reported twice by different axes (run 1 wrote two reports
from two angles). The per-axis count in the ledger counts both files; they are
alternate views of the same incident.

## How findings become rules

Scenarios carry a `coverage` value judged against the rule ids in
`policies/*.yaml` (the researchers grep them at run time) and an
`observable` value: `exec-input` (the monitor sees it today) or
`file-open` / `network-connect` (blocked until the monitor emits that
event kind). The ledger's interruption budget governs which scenarios
become stopping rules; `docs/DETECTION-REQUIREMENTS.md` is the spec that
the catalogue adds up to.
