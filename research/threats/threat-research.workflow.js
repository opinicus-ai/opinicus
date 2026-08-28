// Threat research workflow for the Agent Firewall project.
//
// This file is a script for the pi `workflow` tool. Do not run it with
// node or bun. To run it, the agent reads this file, passes its content
// as `script` and the current ledger as `args` (JSON: {"ledger": "..."}).
//
// The run:
//   1. fans out one research agent per threat axis (web research,
//      incident reports written to research/threats/incidents/),
//   2. merges everything into research/threats/LEDGER.md with stable ids,
//      deduplicated against the ledger passed in args.
//
// See README.md in this directory for the runbook.

export const meta = {
  name: 'threat-research',
  description: 'Deep research: coding-agent failure incidents + firewall block scenarios',
  phases: [{ title: 'Research' }, { title: 'Ledger merge' }],
}

const state = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const LEDGER = state.ledger ?? '(empty ledger: first run)'
const ROOT = '/home/vfeenstr/devel/lab/opinicus-56sol/research/threats'

const CONTEXT = `
PROJECT: Agent Firewall. A local, deterministic security layer ("EDR for coding agents")
that launches a coding agent (Claude Code, Codex, Pi, Gemini CLI, ...) under a ptrace
monitor on Linux and applies policy to what the agent and ALL its descendant processes do.

What the monitor can observe (this is what every scenario must map to):
- exec: program name, exe path, full argv, working directory, environment, process ancestry
- file_open: path, read or write
- network_connect: remote host
- input: script text or stdin text captured before it reaches a shell or interpreter

Policy decisions: allow | allow_once | allow_session | approval_required | deny | terminate.
Builtin policy packs: filesystem, git, process, network, database, cloud (policies/*.yaml).
`

const AXES = [
  {
    code: 'fs',
    title: 'Filesystem destruction and data loss',
    focus: `Agents deleting or overwriting things they should not: rm -rf with wrong or
unquoted variables, destructive moves, truncating files, wiping directories outside the
project, destroying .git or node_modules of other projects, clobbering dotfiles and
configs, symlink targets deleted, recursive chown/chmod damage.`,
  },
  {
    code: 'vcs',
    title: 'Git and version-control damage',
    focus: `Force pushes, deleted branches and tags, rewritten or leaked history, commits
of secrets or large files, pushing to the wrong remote, deleting uncommitted work
(reset --hard, clean -fdx), breaking git hooks, signing-key or identity changes.`,
  },
  {
    code: 'secrets',
    title: 'Secret and credential harvesting',
    focus: `Reading .env files, ssh keys, cloud credentials and browser cookies; env var
dumping; tokens pasted into logs, commits, issues or error reports; agents asked to
"debug auth" that end up shipping credentials to third parties; grep sweeps over home
directories for secrets.`,
  },
  {
    code: 'exfil',
    title: 'Network exfiltration and unauthorized egress',
    focus: `curl/wget of attacker or pastebin URLs, posting collected data to webhooks,
DNS-based exfiltration, data smuggled inside legitimate API traffic, uploads from
scripts, telemetry abuse, connecting to internal services (metadata endpoints, admin
ports) that an agent has no business touching.`,
  },
  {
    code: 'supply',
    title: 'Supply chain: packages, install scripts, builds',
    focus: `Typosquatted and compromised packages, postinstall scripts running as the
agent user, "curl | bash" installers agents love to run, build tools running arbitrary
code from manifests, compromised GitHub Actions, agents that install whatever a README
tells them.`,
  },
  {
    code: 'inject',
    title: 'Prompt injection that turns into real actions',
    focus: `Instructions hidden in READMEs, issues, code comments, error messages, web
pages the agent reads, tool outputs, or config files (rules files, AGENTS.md, CLAUDE.md)
that make the agent run commands, leak data, or weaken its own guardrails. Documented
PoCs and real exploitation reports.`,
  },
  {
    code: 'cloud',
    title: 'Production infrastructure, databases, CI/CD',
    focus: `Agents touching cloud CLIs and consoles: kubectl against production, terraform
destroy/apply, database drops and migrations against live data, serverless redeployments,
CI pipelines edited to run attacker code, DNS or CDN changes, accidental cost spikes.`,
  },
  {
    code: 'mcp',
    title: 'MCP servers and the tool/plugin ecosystem',
    focus: `Malicious or compromised MCP servers (local and remote), tool poisoning and
rug pulls, confused-deputy attacks through MCP tools, slash-command and skill/package
injection, editors and CLI plugins that execute on load.`,
  },
  {
    code: 'behavior',
    title: 'Agent self-inflicted failures',
    focus: `Failure modes of the agent itself: infinite retry loops burning money or API
quota, editing its own configuration or guardrails, killing and restarting its own
process tree, long-running daemons left behind, parallel agents clobbering each other's
files, wrong-target edits after context confusion, hallucinated commands that happen to
exist and do damage, agents un-installing or disabling security tooling.`,
  },
  {
    code: 'evade',
    title: 'Monitor evasion and OS-level tricks (red team)',
    focus: `This is a red-team axis for the firewall itself. How can a monitored process
tree evade observation or fool policy matching? Ideas to research and verify on Linux:
shell builtins that never exec (rm/kill/ulimit built into bash), double-fork/setsid
daemons escaping ancestry tracking, killing or ptrace-attacking the monitor, interpreters
as generic proxies (python -c / perl -e / node -e doing file and network work), memfd_create
and /proc/self/fd execution, LD_PRELOAD and linker tricks, symlink and hardlink relabeling,
TOCTOU between check and action, static or self-compiled binaries from heredocs, base32/hex
variants of known payloads, tar/pipe smuggling, namespace and unshare tricks, writing a
payload via file_open and chmod +x instead of downloading.`,
  },
]

const INCIDENT_SCHEMA = {
  type: 'object',
  properties: {
    slug: { type: 'string' },
    title: { type: 'string' },
    date: { type: 'string' },
    agent_or_tool: { type: 'string' },
    summary: { type: 'string' },
    failure_mechanism: { type: 'string' },
    firewall_lesson: { type: 'string' },
    sources: { type: 'array', items: { type: 'string' } },
    report_file: { type: 'string' },
    status: { type: 'string', enum: ['new-report-written', 'seed-verified', 'known-referenced'] },
  },
  required: ['slug', 'title', 'summary', 'failure_mechanism', 'sources', 'status'],
}

const SCENARIO_SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    category: { type: 'string' },
    behavior: { type: 'string' },
    example: { type: 'string' },
    detection_signal: { type: 'string' },
    suggested_decision: { type: 'string', enum: ['allow', 'approval_required', 'deny', 'terminate'] },
    policy_pack: { type: 'string' },
    coverage: { type: 'string', enum: ['gap', 'partial', 'covered'] },
    severity: { type: 'number' },
    source_slugs: { type: 'array', items: { type: 'string' } },
  },
  required: ['title', 'category', 'behavior', 'example', 'detection_signal', 'suggested_decision', 'policy_pack', 'coverage', 'severity'],
}

const RESEARCH_SCHEMA = {
  type: 'object',
  properties: {
    incidents: { type: 'array', items: INCIDENT_SCHEMA },
    scenarios: { type: 'array', items: SCENARIO_SCHEMA },
    notes: { type: 'string' },
  },
  required: ['incidents', 'scenarios'],
}

const MERGE_SCHEMA = {
  type: 'object',
  properties: {
    incidents_added: { type: 'number' },
    scenarios_added: { type: 'number' },
    duplicates_merged: { type: 'number' },
    ledger_written: { type: 'boolean' },
    summary: { type: 'string' },
  },
  required: ['incidents_added', 'scenarios_added', 'duplicates_merged', 'ledger_written', 'summary'],
}

function researchPrompt(axis) {
  return `You are a security researcher on the Agent Firewall project.
${CONTEXT}
YOUR AXIS: ${axis.title} (axis code "${axis.code}")
${axis.focus}

KNOWN INCIDENT LEDGER (do NOT write a new report for anything listed here; reference by slug):
${LEDGER}

TASK — three deliverables:

1) REAL INCIDENTS. Use web search (and scrape pages that need reading) to find real,
documented incidents where a coding agent (Claude Code, Codex, Cursor, Replit Agent,
Gemini CLI, Windsurf, Aider, Copilot agent mode, Devin, ...) or its toolchain (npm
packages, MCP servers, build tools, dotfiles managers) caused damage of your axis kind.
Verification bar: at least one authoritative URL (vendor postmortem, security company
writeup, official advisory, or reputable news). NEVER invent URLs, dates, numbers or
quotes. If you cannot verify, leave it out. Pick at most the 4 best NEW incidents
(not already in the ledger above, not an axis another known row already covers).

2) INCIDENT REPORTS. For each new incident, write one markdown file with the write tool to
${ROOT}/incidents/${axis.code}-<short-slug>.md   (kebab-case slug, keep it stable, it becomes the row id anchor)

Use exactly this structure:

# <Title>
- Date: <when it happened> | Agent/tool: <what was involved> | Axis: ${axis.code}
## What happened
<4-10 short sentences. Plain English, short sentences, like the project docs.>
## How it went wrong
<the mechanism: what instruction, what command, what process tree, what OS-level events>
## What the firewall should learn
<which observable signal (exec/file_open/network_connect/input + ancestry) would have
caught it, and the rule idea (decision: approval_required, deny, ...)>
## Sources
- [<label>](<url>)

Style rule: plain English, short sentences. After writing the files, verify they exist with ls.

3) TEST SCENARIOS. Derive 8-15 concrete scenarios for your axis that the firewall must
handle (block, gate behind approval, or at least observe and report). Include scenarios
with no public incident if the behavior is plausible or known in the wild; leave
source_slugs empty for those. Fields:
- title: short, behavior-focused ("rm with unquoted variable deletes wrong directory")
- category: one of filesystem|git|process|network|database|cloud|secrets|supply-chain|prompt-injection|agent-behavior|mcp|evasion
- behavior: what happens, in observable OS terms
- example: a concrete command line or event sequence (realistic, minimal)
- detection_signal: phrased ONLY in terms of exec(program/exe/argv/cwd/env/ancestry), file_open(path,write), network_connect(host), input(text)
- suggested_decision: allow (observe only) | approval_required | deny | terminate
- policy_pack: filesystem|git|process|network|database|cloud|cross
- coverage: gap (no builtin rule would match today) | partial | covered
- severity: 1-5 (5 = worst realistic outcome for a developer machine)
Rules: detection_signal must be realistically implementable; if the firewall cannot see
it with the listed observables, say so in the signal and mark coverage "gap" with a note
in behavior. Do not duplicate scenarios the builtin packs already cover unless you mark
them covered.

Special rule for your axis${axis.code === 'evade' ? '' : ' (only if incidents are scarce)'}: for the evasion axis, incidents are
optional — spend the effort on 12-18 scenarios of evasions instead, and verify Linux
mechanics from documentation.

RETURN ONLY the structured result for your axis. Never write files other than your own
incident reports under ${ROOT}/incidents/.`
}

phase('Research')
const results = await parallel(
  AXES.map((axis) => () =>
    agent(researchPrompt(axis), {
      label: `research:${axis.code}`,
      phase: 'Research',
      schema: RESEARCH_SCHEMA,
    }),
  ),
  { concurrency: 4 },
)

const good = results.filter((r) => r.ok && r.structured)
const failed = results.filter((r) => !r.ok)

phase('Ledger merge')
const mergePrompt = `You are the ledger keeper of the Agent Firewall threat research.
${CONTEXT}
CURRENT LEDGER (the source of truth you will rewrite):
${LEDGER}

RESEARCH RESULTS from ${good.length} researchers (JSON):
${JSON.stringify(good.map((r) => r.structured))}

REWRITE ${ROOT}/LEDGER.md with the write tool, applying these rules:

1. Keep the overall section structure of the current ledger (Coverage summary,
   Incident ledger, Scenario ledger, Run log) and the exact column layouts.
2. INCIDENT LEDGER: keep every existing row, same id, same columns. Fix date/title
   if a researcher verified the facts and marked the entry seed-verified with a report
   file. For incidents with status new-report-written or seed-verified, set the report
   column to the actual filename (run: ls ${ROOT}/incidents/ to check which files exist;
   the filename for a row is <axis>-<slug>.md). Rows still without a report keep "missing".
   Append new rows for incidents with status new-report-written, assigning ids
   INC-### continuing from the highest existing id.
3. SCENARIO LEDGER: assign ids SC-### continuing from the highest existing id.
   Deduplicate first: scenarios whose core behavior is the same merge into one row —
   keep the richer title/behavior, union the source slugs, keep the higher severity;
   count merges in duplicates_merged. Columns: id | title | category | pack | decision
   | sev | coverage | status | sources. sources = INC ids (comma separated) or "-".
   New rows get status "proposed". Existing rows keep their existing status
   (proposed / rule-written / tested) even if research re-reports them.
4. COVERAGE SUMMARY: recompute the counts of scenario rows per policy pack
   (filesystem, git, process, network, database, cloud, cross) split by coverage
   (gap, partial, covered). Keep the table shape.
5. RUN LOG: append one row. Get today's date with: date -I. Put incidents added
   (new INC rows), scenarios added (new SC rows after dedup), duplicates merged,
   and a one-line note listing which axes failed to return results, if any:
   ${failed.length ? failed.map((r) => r.error || 'failed').join('; ') : 'none'}
6. Do not editorialize; the ledger is a table document. Keep plain English, short sentences.

Write the complete file, then verify it reads back (wc -l). Return the counts.`

const merged = await agent(mergePrompt, { label: 'ledger-merge', phase: 'Ledger merge', schema: MERGE_SCHEMA })

return {
  axes_run: AXES.map((a) => a.code),
  research_failures: failed.length,
  incidents_found: good.reduce((n, r) => n + r.structured.incidents.length, 0),
  scenarios_found: good.reduce((n, r) => n + r.structured.scenarios.length, 0),
  merge: merged.ok ? merged.structured : { error: merged.error },
}
