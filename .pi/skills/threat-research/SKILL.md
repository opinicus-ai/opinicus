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
   - `args`: JSON string `{"knownReports": [{"f": "<file>.md", "t": "<title>"},
     ...]}` for every report already in `incidents/` (so nothing is researched
     twice). Researchers and the merge agent read `LEDGER.md` and the axis
     catalogs from disk; the script takes no `ledger` arg. Never launch with a
     placeholder or an empty `knownReports`.
   - `background: true`
3. Before announcing the run: read `~/.pi/agent/workflows/<wf-id>/` and confirm
   the parsed args carry the real `knownReports` count. To stop a fresh run,
   identify the runner pid in `ps` output first (other sandboxes may be live),
   kill only that pid, then confirm `git status research/threats/` is untouched.
4. While it runs, tell the user what is happening (10 research agents + ledger merge).
5. When the run settles: run `python3 research/threats/check.py` (must pass
   before committing), `git status research/threats/`, spot-check 2-3 new
   incident reports for invented facts (check their source URLs), and
   summarize: incidents added, scenarios added, coverage gaps.
6. Report follow-up candidates: scenarios with coverage `gap` that deserve a new
   rule in `policies/`, and seed rows still marked report `missing`.

Rules:

- Every run dedupes against what is on disk (axis catalogs + `knownReports`),
  so it is safe to rerun. New scenarios are appended with continuing
  `<axis>-NN` numbers; the merge edits only the ledger's count tables.
- To add or retire research axes, edit `AXES` in `threat-research.workflow.js`.
- Rule-writing is governed by the ledger's interruption budget and
  `docs/DETECTION-REQUIREMENTS.md`, not by this skill.
- When authoring or editing any workflow script (this one or an ad-hoc variant,
  e.g. a single-incident deep dive), agents hand data to later phases by
  writing files under the repo (e.g. `tmp/threats/`) and having the next agent
  `read` them. Never inline one agent's full findings JSON into another
  agent's prompt: a fat prompt fails with "invalid agent request" (the comment
  at the top of `threat-research.workflow.js` says the same).
- Before launching a run, check that the script's CONTEXT block and the
  ledger's observable summary describe the monitor as currently built (event
  kinds, policy packs). If a milestone shipped since the last run, refresh
  both first and run `check.py` before the launch: researchers judge coverage
  against what you tell them the monitor can see.
