// Threat research workflow for the Agent Firewall project.
//
// This file is a script for the pi `workflow` tool. Do not run it with
// node or bun. To run it, the agent reads this file, passes its content
// as `script` and the current state as `args` (JSON):
//   { "ledger": "<content of LEDGER.md>",
//     "knownReports": [{ "f": "<file>.md", "t": "<title>" }, ...] }
// knownReports lists incident reports already on disk (do not redo them).
//
// Current state model (matches the repo after the ledger rebuild):
// - incidents/<axis>-<slug>.md are the incident source of truth.
// - scenarios/<axis>.md are the scenario source of truth; each scenario is a
//   "### SC <axis>-NN <title>" section. Researchers APPEND new sections with
//   continuing numbers; they never rewrite existing ones.
// - LEDGER.md is an analysis document (headline numbers, observable summary,
//   coverage summary, interruption budget, per-axis tables, run log). The
//   merge step updates ONLY its count tables and appends a run log row,
//   with targeted edits; all prose is preserved verbatim.
//
// The run:
//   1. fans out one research agent per threat axis (web research; new incident
//      reports to incidents/, new scenario sections appended to the axis
//      catalog; dedupe against what is already on disk),
//   2. retries an axis once if its agent failed,
//   3. merges a compact digest into LEDGER.md count tables.
// The merge gets only a digest, never the full scenario prose - a fat prompt
// fails with "invalid agent request".
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
const ROOT = '/home/vfeenstr/devel/lab/opinicus-56sol/research/threats'
const POLICIES = '/home/vfeenstr/devel/lab/opinicus-56sol/policies'

const CONTEXT = `
PROJECT: Agent Firewall. A local, deterministic security layer ("EDR for coding agents")
that launches a coding agent (Claude Code, Codex, Pi, Gemini CLI, ...) under a ptrace
monitor on Linux and applies policy to what the agent and ALL its descendant processes do.

What the monitor of the CURRENT version can observe:
- exec: program name, exe path, full argv, working directory, environment, process ancestry
- input: script text or stdin text captured before it reaches a shell or interpreter
- file_open and network_connect exist in the rule language but the current monitor does
  not emit them yet; scenarios that need them are counted as "blocked on an observable".

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
shell builtins that never exec, double-fork/setsid daemons escaping ancestry tracking,
killing or ptrace-attacking the monitor, interpreters as generic proxies, memfd_create
and /proc/self/fd execution, LD_PRELOAD and linker tricks, symlink and hardlink relabeling,
TOCTOU between check and action, self-compiled binaries from heredocs, base32/hex payload
variants, tar/pipe smuggling, namespace and unshare tricks, io_uring batch I/O.`,
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
    status: { type: 'string', enum: ['new-report-written', 'known-referenced'] },
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
    needs_observable: { type: 'string', enum: ['exec-input', 'file-open', 'network-connect'] },
    source_slugs: { type: 'array', items: { type: 'string' } },
  },
  required: ['title', 'category', 'pack', 'decision', 'severity', 'coverage', 'needs_observable'],
}

const RESEARCH_SCHEMA = {
  type: 'object',
  properties: {
    incidents: { type: 'array', items: INCIDENT_SCHEMA },
    scenarios: { type: 'array', items: SCENARIO_SCHEMA },
    catalog_file: { type: 'string' },
    scenarios_appended: { type: 'number' },
    notes: { type: 'string' },
  },
  required: ['incidents', 'scenarios', 'catalog_file', 'scenarios_appended'],
}

const MERGE_SCHEMA = {
  type: 'object',
  properties: {
    incidents_added: { type: 'number' },
    scenarios_added: { type: 'number' },
    ledger_updated: { type: 'boolean' },
    summary: { type: 'string' },
  },
  required: ['incidents_added', 'scenarios_added', 'ledger_updated', 'summary'],
}

function researchPrompt(axis, retry) {
  return `You are a security researcher on the Agent Firewall project.${retry ? '\nA previous attempt at this axis died; work efficiently and return your structured result.' : ''}
${CONTEXT}
YOUR AXIS: ${axis.title} (axis code "${axis.code}")
${axis.focus}

STEP 0 — READ WHAT EXISTS. This is a rerun of an established research program.
1. Read ${ROOT}/scenarios/${axis.code}.md — the catalog of ${axis.code} scenarios that
   already exist (headings look like "### SC ${axis.code}-01 <title>"). NEVER rewrite,
   renumber or delete existing sections. You APPEND new ones only, with continuing
   numbers, inserted right after the last "### SC" section (before any trailing prose).
2. Run: grep -h 'id:' ${POLICIES}/*.yaml — these are the rule ids that exist today.
   Judge every coverage value against these real rules, not against an imagined pack.
3. Read the current ledger section "Known blind spots" in: ${ROOT}/LEDGER.md

INCIDENT REPORTS ALREADY ON DISK (never rewrite or duplicate these; you may reference a
report by its filename without the .md as a source slug):
${KNOWN}

PRIORITY THIS RUN: incident coverage is broad (57 reports). Find at most 1-2 genuinely
NEW incidents for your axis; if nothing new is worth reporting, report zero and put all
effort into scenarios that the existing catalogs do not have yet. A rerun that returns
only a handful of high-quality new items is a success; re-deriving known scenarios is a
failure.

TASK — two deliverables:

1) NEW INCIDENT REPORTS (at most 2). For each, write one markdown file with the write
tool to ${ROOT}/incidents/${axis.code}-<short-slug>.md (kebab-case, stable). Structure:

# <Title>
- Date: <when> | Agent/tool: <what was involved> | Axis: ${axis.code}
## What happened
<4-10 short sentences, plain English.>
## How it went wrong
<mechanism: instruction, command, process tree, OS-level events>
## What the firewall should learn
<observable signal (exec/input + ancestry, or a missing observable) and the rule idea>
## Sources
- [<label>](<url>)

Verification bar: at least one authoritative URL you actually loaded (search + scrape).
NEVER invent URLs, dates, numbers or quotes. If unverifiable, drop it.

2) NEW SCENARIOS appended to your catalog (the main deliverable). Derive only scenarios
NOT already in the catalog. Realistic targets for a rerun: 2-6 new ones. Append one
section per scenario to ${ROOT}/scenarios/${axis.code}.md with the write or edit tool:

### SC ${axis.code}-<NN+1> <title>
- category: <filesystem|git|process|network|database|cloud|secrets|supply-chain|prompt-injection|agent-behavior|mcp|evasion>
- decision: <allow|approval_required|deny|terminate> | severity: <1-5>
- pack: <filesystem|git|process|network|database|cloud|cross> | coverage: <gap|partial|covered>
- observable: <exec-input|file-open|network-connect>
- sources: <incident slugs or ->
behavior: <what happens, in observable OS terms>
example: <a concrete command line or event sequence>
signal: <phrased ONLY in terms of exec(program/exe/argv/cwd/env/ancestry), input(text), file_open(path,write), network_connect(host); say which observable it needs>

"observable" is the ONE the signal fundamentally needs: exec-input when the monitor can
see it today; file-open or network-connect when the scenario is blind until that event
kind exists. Match the style and depth of the existing sections in the file.

3) STRUCTURED RESULT. Return ONLY the new items: incidents (slug, title, date, axis,
one-line summary, firewall_lesson, sources, report_file, status) and the new scenarios
(short fields only: title, category, pack, decision, severity, coverage, needs_observable
= the observable value, source_slugs). scenarios_appended = how many sections you added.
The prose lives in the catalog file, do not repeat it in the result.

Never write files other than: your new incident reports under ${ROOT}/incidents/ and
appends to ${ROOT}/scenarios/${axis.code}.md. Verify with ls and tail before returning.`
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
    report_file: i.report_file ?? '', status: i.status, sources: i.sources ?? [],
  })),
  scenarios: r.structured.scenarios,
}))

const mergePrompt = `You are the ledger keeper of the Agent Firewall threat research.
The ledger at ${ROOT}/LEDGER.md is an ANALYSIS DOCUMENT: headline numbers, observable
summary, coverage summary, the interruption budget, per-axis tables, known blind spots,
run log. Its prose and structure were carefully built and must be preserved.

NEW RESEARCH DIGEST (JSON; the full prose lives in incidents/ and scenarios/<axis>.md):
${JSON.stringify(digest)}

Update the ledger with the edit tool (targeted replacements ONLY — never rewrite the
whole file), applying these rules:

1. Count the new incidents (status new-report-written) and new scenarios from the digest.
2. "Headline numbers" table: add the deltas. incident reports count += new incidents;
   scenarios count += new scenarios; "scenarios the monitor can see today" += new
   scenarios whose needs_observable is exec-input; "scenarios that need an observable
   the monitor does not make" += the rest. Also update the percent line under the
   Observable summary if the numbers moved (recompute from the table values).
3. "Observable summary" table: add the same deltas to its two rows.
4. "Coverage summary" table (per policy pack, columns gap/partial/blocked/actionable):
   for each new scenario, add 1 to its pack row: gap or partial per its coverage value
   (covered adds nothing and is not in the table); blocked += 1 if needs_observable is
   not exec-input; actionable = previous actionable + (1 if exec-input and coverage is
   gap or partial else 0). Recompute the total row.
5. "Incident ledger" per-axis report-count table: recount or increment the axis rows and
   keep the table sorted as it is.
6. "Scenario ledger" per-axis table (columns: scenarios | gap | partial | blocked on an
   observable): increment the axis row of each new scenario the same way. Then refresh
   the sentence under the table that names the most blocked axes, only if the leader
   changed.
7. "Run log": append one row. Columns are: date | incidents | scenarios | notes. Get
   today's date with: date +%Y-%m. notes = one short line: how many new incidents and
   scenarios this rerun added, and which axes returned nothing new:
   ${failed.length ? 'unknown at merge time, see run output' : 'no axis failed'}
8. Do NOT touch any other section or sentence. If a table cell would become wrong,
   fix only that cell. Plain English, short sentences.

Verify by reading the changed sections back. Return the counts.`

const merged = await agent(mergePrompt, { label: 'ledger-merge', phase: 'Ledger merge', schema: MERGE_SCHEMA })

return {
  axes_run: AXES.map((a) => a.code),
  research_failures: failed.length,
  incidents_found: good.reduce((n, r) => n + r.structured.incidents.length, 0),
  scenarios_found: good.reduce((n, r) => n + r.structured.scenarios.length, 0),
  merge: merged.ok ? merged.structured : { error: merged.error },
}
