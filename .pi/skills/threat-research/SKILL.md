---
name: threat-research
description: Run or extend the Agent Firewall threat research workflow. Use when the user asks to find more block scenarios, run threat research, update the incident ledger, or feed the policy packs with new dangerous-behavior scenarios.
---

# Threat research workflow

The project keeps a ledger of coding-agent failure incidents and firewall test
scenarios in `research/threats/`. A reusable multi-agent workflow researches
the web, writes incident reports, and merges everything into the ledger.

Runbook (also in `research/threats/README.md`):

1. Read `research/threats/LEDGER.md` and `research/threats/threat-research.workflow.js`.
2. Call the `workflow` tool with:
   - `script`: the full content of `research/threats/threat-research.workflow.js`
   - `args`: JSON string with the current state:
     - `ledger`: full current content of `research/threats/LEDGER.md`
     - `knownReports`: `[{"f": "<file>.md", "t": "<title>"}, ...]` for every
       report already in `incidents/` (so nothing is researched twice)
     - `seedTodo`: `[{"id": "INC-001", "axis": "cloud", "slug": "...",
       "title": "...", "source": "https://..."}, ...]` for ledger rows whose
       report column is still `missing`
   - `background: true`
3. While it runs, tell the user what is happening (10 research agents + ledger merge).
4. When the run settles: `git status research/threats/`, spot-check 2-3 new
   incident reports for invented facts (check their source URLs), and summarize:
   incidents added, scenarios added, coverage gaps.
5. Report follow-up candidates: scenarios with coverage `gap` that deserve a new
   rule in `policies/`, and seed rows still marked report `missing`.

Rules:

- Every run dedupes against the ledger passed in `args`, so it is safe to rerun.
- To add or retire research axes, edit `AXES` in `threat-research.workflow.js`.
- Scenario status moves proposed -> rule-written (rule id exists in `policies/`)
  -> tested (rule has yaml tests). Update the ledger by hand when rules land,
  and record the rule id in the scenario row's sources column.
