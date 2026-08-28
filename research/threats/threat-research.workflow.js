// Threat research workflow for the Agent Firewall project.
//
// This file is a script for the pi `workflow` tool. Do not run it with
// node or bun. To run it, the agent reads this file, passes its content
// as `script` and the current state as `args` (JSON):
//   { "ledger": "<content of LEDGER.md>",
//     "knownReports": [{ "f": "<file>.md", "t": "<title>" }, ...],
//     "seedTodo": [{ "id": "INC-001", "axis": "cloud", "slug": "...",
//                    "title": "...", "source": "https://..." }, ...] }
// knownReports lists incident reports already on disk (do not redo them).
// seedTodo lists ledger rows that still need their report written.
//
// The run:
//   1. fans out one research agent per threat axis (web research; incident
//      reports to incidents/, scenario catalogs to scenarios/<axis>.md),
//   2. retries an axis once if its agent failed,
//   3. merges a compact digest into research/threats/LEDGER.md with stable
//      ids, deduplicated against the ledger passed in args.
// The merge gets only a digest (title/category/pack/decision/severity/
// coverage/sources), never the full scenario prose - a fat prompt fails
// with "invalid agent request". Full details live on disk in scenarios/.
//
// See README.md in this directory for the runbook.

export const meta = {
  name: 'threat-research',
  description: 'Deep research: coding-agent failure incidents + firewall block scenarios',
  phases: [{ title: 'Research' }, { title: 'Ledger merge' }],
}

const state = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const LEDGER = state.ledger ?? '(empty ledger: first run)'
const KNOWN = (state.knownReports ?? []).map((r) => `- ${r.f} | ${r.t}`).join('\n') || '(none)'
const SEEDS = state.seedTodo ?? []
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
    axis: { type: 'string' },
    summary: { type: 'string' },
    firewall_lesson: { type: 'string' },
    sources: { type: 'array', items: { type: 'string' } },
    report_file: { type: 'string' },
    seed_id: { type: 'string' },
    status: { type: 'string', enum: ['new-report-written', 'seed-verified', 'known-referenced'] },
  },
  required: ['slug', 'title', 'axis', 'summary', 'sources', 'report_file', 'status'],
}

const SCENARIO_SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    category: { type: 'string' },
    pack: { type: 'string' },
    decision: { type: 'string', enum: ['allow', 'approval_required', 'deny', 'terminate'] },
    severity: { type: 'number' },
    coverage: { type: 'string', enum: ['gap', 'partial', 'covered'] },
    source_slugs: { type: 'array', items: { type: 'string' } },
  },
  required: ['title', 'category', 'pack', 'decision', 'severity', 'coverage'],
}

const RESEARCH_SCHEMA = {
  type: 'object',
  properties: {
    incidents: { type: 'array', items: INCIDENT_SCHEMA },
    scenarios: { type: 'array', items: SCENARIO_SCHEMA },
    catalog_file: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['incidents', 'scenarios', 'catalog_file'],
}

const MERGE_SCHEMA = {
  type: 'object',
  properties: {
    incidents_added: { type: 'number' },
    seed_reports_linked: { type: 'number' },
    scenarios_added: { type: 'number' },
    duplicates_merged: { type: 'number' },
    ledger_written: { type: 'boolean' },
    summary: { type: 'string' },
  },
  required: ['incidents_added', 'seed_reports_linked', 'scenarios_added', 'duplicates_merged', 'ledger_written', 'summary'],
}

function seedLinesFor(axis) {
  const mine = SEEDS.filter((s) => s.axis === axis.code)
  if (!mine.length) return '(no seed assignments for your axis)'
  return mine
    .map((s) => `- ${s.id}: write ${axis.code}-${s.slug}.md — "${s.title}" — start from ${s.source}`)
    .join('\n')
}

function researchPrompt(axis, retry) {
  return `You are a security researcher on the Agent Firewall project.${retry ? '\nA previous attempt at this axis died; work efficiently and return your structured result.' : ''}
${CONTEXT}
YOUR AXIS: ${axis.title} (axis code "${axis.code}")
${axis.focus}

INCIDENT REPORTS ALREADY ON DISK (never rewrite or duplicate these; you may reference a
report by its filename without the .md as a source slug):
${KNOWN}

SEED ASSIGNMENTS for your axis (ledger rows still missing a report — write these FIRST,
verify facts and dates against the source, set seed_id to the given id, status seed-verified):
${seedLinesFor(axis)}

PRIORITY THIS RUN: incident coverage is already broad. Spend MOST of your effort on the
scenario catalog. Find at most 1-2 genuinely new incidents for your axis; if nothing new
is worth reporting, report zero new incidents and put all effort into scenarios.

TASK — three deliverables:

1) SEED + NEW INCIDENT REPORTS. For each seed and each new incident, write one markdown
file with the write tool to ${ROOT}/incidents/<axis>-<short-slug>.md (kebab-case, stable).
Structure exactly:

# <Title>
- Date: <when> | Agent/tool: <what was involved> | Axis: ${axis.code}${SEEDS.length ? '' : ''}
## What happened
<4-10 short sentences, plain English.>
## How it went wrong
<mechanism: instruction, command, process tree, OS-level events>
## What the firewall should learn
<observable signal (exec/file_open/network_connect/input + ancestry) and the rule idea>
## Sources
- [<label>](<url>)

Verification bar for NEW incidents: at least one authoritative URL you actually loaded
(search + scrape). NEVER invent URLs, dates, numbers or quotes. If unverifiable, drop it.

2) SCENARIO CATALOG (the main deliverable). Derive 10-15 concrete scenarios for your axis
that the firewall must handle (block, gate behind approval, or at least observe and
report). Write the FULL catalog with all detail to
${ROOT}/scenarios/${axis.code}.md with the write tool, one section per scenario:

### SC <title>
- category: <filesystem|git|process|network|database|cloud|secrets|supply-chain|prompt-injection|agent-behavior|mcp|evasion>
- decision: <allow|approval_required|deny|terminate> | severity: <1-5>
- pack: <filesystem|git|process|network|database|cloud|cross> | coverage: <gap|partial|covered>
- sources: <incident slugs or ->
behavior: <what happens, in observable OS terms>
example: <a concrete command line or event sequence>
signal: <phrased ONLY in terms of exec(program/exe/argv/cwd/env/ancestry), file_open(path,write), network_connect(host), input(text); if the firewall cannot see it with these, say so and mark coverage "gap">

3) STRUCTURED RESULT. Return one scenario entry per catalog section with the SHORT fields
(title, category, pack, decision, severity, coverage, source_slugs) — the prose lives in
the catalog file, do not repeat it in the result. For incidents return: slug, title, date,
axis, one-line summary, firewall_lesson, sources, report_file, seed_id (empty unless it is
a seed), status (new-report-written | seed-verified | known-referenced).

Rules: detection signals must be realistically implementable from the listed observables.
Do not duplicate what the builtin packs already cover unless you mark it covered. Never
write files other than: your incident reports under ${ROOT}/incidents/ and exactly one
catalog ${ROOT}/scenarios/${axis.code}.md. Verify both with ls before returning.`
}

phase('Research')
async function runAxis(axis, retry) {
  return agent(researchPrompt(axis, retry), {
    label: `research:${axis.code}${retry ? ':retry' : ''}`,
    phase: 'Research',
    schema: RESEARCH_SCHEMA,
  })
}

const first = await parallel(AXES.map((a) => () => runAxis(a, false)), { concurrency: 4 })
const retries = await parallel(
  AXES.map((a, i) => () => (first[i].ok ? null : runAxis(a, true))),
  { concurrency: 4 },
)
const results = first.map((r, i) => (r.ok ? r : (retries[i] ?? r)))
const good = results.filter((r) => r.ok && r.structured)
const failed = results.filter((r) => !r.ok)

phase('Ledger merge')
// Compact digest only - the merge agent must not receive full scenario prose.
const digest = good.map((r) => ({
  incidents: r.structured.incidents.map((i) => ({
    slug: i.slug, title: i.title, date: i.date ?? '', axis: i.axis,
    report_file: i.report_file ?? '', seed_id: i.seed_id ?? '',
    status: i.status, sources: i.sources ?? [],
  })),
  scenarios: r.structured.scenarios,
  catalog_file: r.structured.catalog_file,
}))

const mergePrompt = `You are the ledger keeper of the Agent Firewall threat research.
CURRENT LEDGER (the source of truth you will rewrite):
${LEDGER}

RESEARCH DIGEST from ${good.length} researchers (JSON; full scenario prose lives in
${ROOT}/scenarios/<axis>.md and is NOT part of the ledger):
${JSON.stringify(digest)}

REWRITE ${ROOT}/LEDGER.md with the write tool, applying these rules:

1. Keep the section structure (Coverage summary, Incident ledger, Scenario ledger,
   Run log) and the exact column layouts.
2. INCIDENT LEDGER: keep every existing row and its id. For digest incidents with a
   seed_id matching an existing row, set that row's report column to report_file
   (verify against: ls ${ROOT}/incidents/). Append new rows for incidents with status
   new-report-written and empty seed_id, ids INC-### continuing from the highest
   existing id, axis column = the digest axis, report column = report_file,
   sources = first source URL. Rows still without a report keep "missing".
3. SCENARIO LEDGER: one row per digest scenario after dedup. Dedup: same core behavior
   merges into one row — keep the richer title, union source slugs, keep higher severity;
   count merges in duplicates_merged. Ids SC-### continuing from the highest existing id.
   Columns: id | title | category | pack | decision | sev | coverage | status | sources.
   sources = INC ids derived from the source slugs' ledger rows, or "-". New rows get
   status "proposed"; existing rows keep their existing status.
4. COVERAGE SUMMARY: counts of scenario rows per pack (filesystem, git, process, network,
   database, cloud, cross) split by coverage (gap, partial, covered).
5. RUN LOG: append one row. Get today's date with: date -I. incidents added = new INC rows,
   scenarios added = new SC rows after dedup, duplicates merged, notes = failed axes:
   ${failed.length ? failed.map((_, i) => AXES[i]?.code ?? '?').join(', ') : 'none'}
6. Plain English, short sentences, no editorializing. Write the complete file, then
   verify with wc -l. Return the counts.`

const merged = await agent(mergePrompt, { label: 'ledger-merge', phase: 'Ledger merge', schema: MERGE_SCHEMA })

return {
  axes_run: AXES.map((a) => a.code),
  research_failures: failed.length,
  incidents_found: good.reduce((n, r) => n + r.structured.incidents.length, 0),
  scenarios_found: good.reduce((n, r) => n + r.structured.scenarios.length, 0),
  merge: merged.ok ? merged.structured : { error: merged.error },
}
