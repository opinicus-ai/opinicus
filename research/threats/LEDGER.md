# Threat research ledger

The ledger lists every incident and every block scenario that the threat
research found. One row per item. Stable identifiers never change.

Sections:

- Coverage summary: how well the builtin policy packs cover the scenarios.
- Incident ledger: real, documented cases where a coding agent went wrong.
- Scenario ledger: concrete behaviors the firewall should handle. The status
  moves from `proposed` to `rule-written` (a rule id exists in `policies/`)
  to `tested` (the rule has tests that prove it).
- Run log: one row per research run.

Maintained by the reusable workflow in `threat-research.workflow.js`. See
`README.md` for how to run it again.

## Coverage summary

| policy pack | gap | partial | covered |
| --- | --- | --- | --- |
| (first run fills this) | | | |

## Incident ledger

| id | date | title | axis | report | sources |
| --- | --- | --- | --- | --- | --- |
| INC-001 | 2025-07 | Replit coding agent deleted a production database during a "vibe coding" session | cloud | missing | https://www.businessinsider.com/replit-ceo-apologizes-after-ai-coding-assistant-deletes-company-database-2025-7 |
| INC-002 | 2025-08 | Nx "s1ngularity" supply-chain attack abused local AI CLIs to harvest credentials | supply | missing | https://nx.dev/blog/nx-security-alert |
| INC-003 | 2025-09 | "Shai-Hulud" self-replicating npm worm, called the first npm supply-chain worm | supply | missing | https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack |
| INC-004 | 2025-09 | chalk and debug npm packages compromised, malicious code shipped to millions | supply | missing | https://github.com/debug-js/debug/issues/1000 |
| INC-005 | 2025-07 | Amazon Q developer agent compromised via a crafted pull request on GitHub | supply | missing | https://www.lasso.security/blog/amazon-q-ai-agent-hijack-attempt |
| INC-006 | 2025-11 | Malicious postmark-mcp MCP server blind-copied user emails to the attacker | mcp | missing | https://www.koi.ai/blog/postmark-mcp-malicious-package-backdoor |
| INC-007 | 2025-08 | Gemini CLI tricked by a malicious GitHub issue into exfiltrating data (PoC) | inject | missing | https://tracebit.com/blog/gemini-cli-data-exfiltration-poc |
| INC-008 | 2025-04 | Cursor "rules file backdoor": persistent instruction injection through rules files | inject | missing | https://www.hiddenlayer.com/novusbullentine/2025/cursor-rules-file-backdoor |

Rows with report `missing` still need a full incident report in `incidents/`.
Research runs verify the seeds (date, facts, source) and write the reports.

## Scenario ledger

| id | title | category | pack | decision | sev | coverage | status | sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Run log

| date | incidents added | scenarios added | duplicates merged | notes |
| --- | --- | --- | --- | --- |
| (first run pending) | | | | ledger created |
