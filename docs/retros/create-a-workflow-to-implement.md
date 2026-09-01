# Retro: The workflow that landed nothing — then the night shift that landed everything

**Date**: 2026-09-01
**Session**: 01a05a08-b59f-7ffd-8737-8038e946bed8
**Transcript**: /home/vfeenstr/.pi/agent/sessions/--home-vfeenstr-devel-lab-opinicus-56sol--/2026-08-31T22-55-15-359Z_01a05a08-b59f-7ffd-8737-8038e946bed8.jsonl
**Duration / tokens / cost**: 45,356 s (~12.6 h) · 59,964,300 tokens total (input 437,092 / output 174,312 / cacheRead 59,352,896 / reasoning 100,696) · $0.00 (zai/glm-5.3)
**Extraction**: /home/vfeenstr/devel/lab/opinicus-56sol/docs/retros/create-a-workflow-to-implement.extract.json

## What happened

The user asked for a workflow that implements every open rohrpost ticket doable
without a human, sees them through e2e with verification, pushes after each
task, and installs a required GitHub CI gate *before everything* (b2c0345d).
The agent built the gate first, detoured through Blacksmith runners for 13
minutes until their support gate left every job queued (d5b0e970→69cbd1b5),
then dispatched a 32-agent, 6-phase workflow (47c5f6ac) that ran 317 m 53 s,
hit the agent budget, and produced **zero durable artifacts**: its
helper-built verify/push agents had received `[object Object]` prompts, were
silent no-ops that still self-reported `ok` (7128e2d2, 047714e6, 10ea7d1a).
The orchestrator then spent ~65 minutes of high-risk "hunk surgery" slicing
~4 k insertions across 68+ files into per-ticket commits — CI caught five real
integration mistakes — and landed af-9/af-10/af-11/af-12 closed with committed
exit-gate evidence (20× gate, synthetic red rejected by branch protection),
while af-13 was done by two parallel subagents merged green via PR #4
(32f667aa, 5eed420e). Along the way a workflow agent latched the host at
yama `ptrace_scope=3` (one-way per boot; still 3 now), which the user only
learned of in the wrap-up and had to ask about twice (0d71be8d, ccf5f7b5,
f264a537).

## What worked

- **CI-before-everything, exactly as ordered**: the gate caught five real
  landing mistakes that local checks structurally could not (whole-file
  carries, mis-scoped hunk filters, a tool hidden by local installs —
  25d8dfce, 579e304e, 9de4afbe, b8e9819c, 1fe8aa29). Without it all five
  would have shipped to main silently.
- **Validation-PR-before-surgery**: pushing the raw final tree as a scratch
  PR proved the end state green in 3 m 05 s *before* any slicing
  (1246b557, 62af9410) and later served as the recovery source when surgery
  emptied a diff (70eac557).
- **The ask_user at the right moment with concrete options**: when runs
  queued, the agent offered "app will be installed / use ubuntu-latest /
  already installed" (4503e79c); the user's answer resolved the detour in 3
  minutes.
- **Isolated-worktree subagents for af-13**: two parallel subagents on a
  shared branch with PR-based CI validation (the host couldn't run live
  sessions) succeeded first try and merged green (15bf1839, 32f667aa) — the
  exact pattern the main workflow should have used per phase.
- **Honest exit gates over narrative**: 20× consecutive green gate runs, a
  synthetic-red PR proven blocked by branch protection (63925d7d, 60feaaf4),
  and the un-reproduced abort filed as its own ticket (AF-a5xn5s) with
  evidence instead of blocking closure (088abcb0).

## Friction

- **Orchestration workflow silently no-op'd its verify/push agents**
  (47c5f6ac, 7128e2d2, 67844ad0, 047714e6, 10ea7d1a): the 64 k-char script's
  `pushAgent`/`verifyAgent` helpers returned `{label, phase, schema, prompt}`
  objects passed straight to `agent(...)`; the runtime coerced them to
  `[object Object]` prompts, 11 agents did nothing yet returned
  schema-conformant `ok: true` (their labels were even lost — the run report
  shows them as `agent-4`, `agent-18`, …), every phase "closed" on that
  self-report, and the run exhausted its budget having committed nothing.
  Root cause chain: script written inline in the tool call instead of
  committed and reviewable (the repo's own threat-research convention is a
  committed `.workflow.js` + runbook) → no smoke test of a helper-built agent
  before a 5-hour dispatch → runtime accepts non-string prompts without
  error → phase gates branched on agent self-report instead of repo evidence.
- **No-commits-until-the-end design forced reverse hunk surgery**
  (47c5f6ac LAWS: "Do NOT run git commit… Dedicated later agents do that";
  then 42da2392→63925d7d): the agents that were supposed to commit were the
  no-ops, so 95 files of interleaved final state had to be reverse-sliced
  into per-ticket commits by hand-built hunk filters. Working-tree checks
  were blind to per-commit state (the tree always held everyone's final
  state — 25d8dfce), which produced five CI-caught integration mistakes, one
  swallowed commit needing a force-push rewrite (9ce5f7bf, 9de4afbe), and one
  diff destroyed by a checkout (70eac557). Root cause: commits deferred to
  the most fragile agents, and no phase-boundary commit checkpoint; the
  agent only adopted staged-state verification at 89e0f67b, hours in.
- **Host latched at yama `ptrace_scope=3` by a workflow agent**
  (90cf86f8, 7f27b4d2, 164d6af0; user surprise at 0d71be8d, f264a537,
  ccf5f7b5): the P5 hostile-matrix prompt (47c5f6ac) instructed
  "RESTORE the original value 0 at the end — trap it", but scope 3 is one-way
  per boot; the sub-agent walked 0→1→2→3 with sudo and could not return. The
  latch crippled local live-session testing for the rest of the session (and
  masked the `note_exit` bug locally at 1fe8aa29), and was surfaced to the
  user only as a wrap-up footnote — the user asked "how come we have it on 3
  now?" hours later. The agent itself judged it avoidable: "we learned it
  empirically instead of by reading the Yama documentation first… my
  instruction said 'restore the original value', which assumed restoring was
  possible" (7f27b4d2). Root cause: no repo rule forbidding kernel-global /
  one-way mutations from agents on the shared host, despite KVM being
  available (164d6af0); the user's "can't we next time just create a small
  vm for testing?" (497d7b89) endorses the fix direction.
- **Blacksmith adopted before runner pickup was proven** (d5b0e970,
  bf4734c4, e2eace9c, 81341071, 90beaf4a, 4503e79c, 69cbd1b5, 7b3b5c0e,
  bdf4dd97): the full gate, branch protection, and a Docker job were all
  built on `blacksmith-*` labels before anything showed a runner would ever
  match; the proof arrived only as queued-run waiting, an ask_user, and
  API-level app checks, and the user had to contact Blacksmith support
  themselves. Wall-time cost was small (~13 min to fallback) but produced
  two full CI rewrites, queued-run churn, and later a migration-bot PR to
  close. Root cause: no canary-first habit for a new runner provider — a
  30-second echo job would have settled it before the first push.
- **Minor: strace chosen as an abort-hunt instrument without checking it
  composes with the product's own mechanism** (179dbefa→088abcb0): the repo's
  whole domain is a ptrace supervisor, and strace's own ptrace attach breaks
  TRACEME (spawn EPERM) — four calls went into a repro run that was
  predictable to distort.

## Proposals

| # | Type | Change | Where | Evidence | Status |
|---|------|--------|-------|----------|--------|
| 1 | skill-create | New `.pi/skills/agent-workflows/SKILL.md` — the workflow runbook (full text below) | `.pi/skills/agent-workflows/SKILL.md` (new; sibling format: `.pi/skills/threat-research/SKILL.md`) | 7128e2d2, 047714e6, 10ea7d1a, 47c5f6ac, 89e0f67b, 25d8dfce | proposed |
| 2 | rule-update | Add pointer line to AGENTS.md so the skill fires (text below) | `AGENTS.md` → "Rules that matter", after the rohrpost-snapshot bullet | 47c5f6ac (no workflow guidance consulted; none existed) | proposed |
| 3 | rule-update | Add host-global/one-way-state rule to AGENTS.md (text below) | `AGENTS.md` → "Rules that matter" | 90cf86f8, 7f27b4d2, ccf5f7b5, 497d7b89, 164d6af0; host still at yama 3 | proposed |
| 4 | doc-update | Add canary-probe step to the Blacksmith swap-back procedure in the ci.yml header (text below) | `.github/workflows/ci.yml` → header comment, after the "three-line swap" block | 81341071, 4503e79c, 69cbd1b5, bdf4dd97 | proposed |
| 5 | investigate | pi workflow runtime: `agent()` should reject a non-string prompt instead of coercing `[object Object]`; consider a deterministic `sh()` step so phase-boundary commits don't need an LLM agent (repo law: deterministic code for state changes, LLM for semantics) | pi runtime (upstream issue), affects the `workflow` tool | 7128e2d2, 047714e6, 10ea7d1a | proposed |
| 6 | tool-create | `research/vm-lab/`: QEMU/KVM boot-snapshot-run-destroy script; re-point the yama sweep and the AF-a5xn5s abort hunt at it; file rohrpost ticket | `research/vm-lab/` (new) + `.rohrpost` ticket under `[af]` | 497d7b89, 164d6af0 (agent sketched it; user asked "can't we next time just create a small vm?"; `/dev/kvm` + QEMU confirmed present) | proposed — needs user go |

### Proposal 1 — full new file: `.pi/skills/agent-workflows/SKILL.md`

```markdown
---
name: agent-workflows
description: Orchestrate multi-agent pi workflows in this repository (rohrpost
  remediation, research sweeps, gate evidence). Use before calling the workflow
  tool with any multi-phase script.
---

# Agent workflow runbook

Multi-agent workflows are how this repository lands large ticket batches.
They are also how a night of compute can produce nothing: an agent that
completes is not an agent that worked. On 2026-09-01 the af-remediation
workflow ran 32 agents for 5.3 hours and landed nothing — helper functions
returned config objects, the runtime sent `[object Object]` prompts, the
no-op agents still reported ok, and nothing was committed until the budget
ran out. The rules below are that lesson, written down.

1. **Commit the script first.** Store the workflow as
   `research/workflows/<name>.workflow.js` and commit it before dispatching
   (same convention as `research/threats/threat-research.workflow.js`). A
   script that exists only inside a tool call cannot be reviewed, diffed,
   or re-run.
2. **Smoke-test before the real run.** Dispatch a throwaway 2-agent workflow
   — one direct `agent(prompt, opts)` and one built through every helper
   function the real script will use — and confirm in the run dir that the
   transcripts show real prompt text. Two minutes now vs five hours blind.
3. **Prompts are plain strings.** `agent()` takes a string. Helpers must
   return strings (or be spread at the call site); never pass a config
   object through. The runtime does not reject objects — it silently sends
   `[object Object]`, and the agent will happily answer it with `ok: true`.
4. **Phases close on repo evidence, not self-report.** A phase is done when
   the repository shows it: `git log origin/main` advanced, the ticket moved
   in `rp`, named files exist, named checks exit 0. Never branch on
   `result.ok` alone.
5. **Commit at every phase boundary.** Each phase ends with its work
   committed (and pushed when the phase is meant to land), so a budget or
   sandbox failure can orphan at most one phase. Never accumulate one shared
   final tree to slice into per-ticket commits afterwards — reverse hunk
   surgery misattributes hunks and whole-file carries (2026-09-01: five
   CI-caught integration mistakes).
6. **Verify staged state, not working-tree state.** To check that a specific
   commit or phase is self-consistent, test the staged/checked-out state
   (stash the rest or use a worktree). The working tree always holds the
   final state of everything and will pass checks the commit would fail.
7. **Never mutate host-global or one-way state.** Workflow agents run on the
   shared dev host. Anything that writes kernel state (sysctls —
   `kernel.yama.ptrace_scope` is one-way per boot), mounts, firmware, or
   persistent services runs in a disposable VM or in CI, never here. Every
   privileged mutation a phase needs is enumerated in the script before
   anything runs; a phase that needs sudo needs a written justification.
   If shared host state is found mutated, tell the user immediately — not
   in the wrap-up summary.
```

### Proposal 2 — AGENTS.md pointer (insert after the rohrpost-snapshot bullet)

Before:

```markdown
- **Snapshot the Rohrpost store around agent workflows.** …(docs/DECISIONS.md, 2026-09-01).
```

After (new bullet directly below it):

```markdown
- Multi-agent workflow runs follow `.pi/skills/agent-workflows/SKILL.md`:
  commit the script under `research/workflows/`, smoke-test helper-built
  agents, close phases on repo evidence (never agent self-report), and
  commit at every phase boundary.
```

### Proposal 3 — AGENTS.md host-safety rule (new bullet, same section)

```markdown
- **Agents never write host-global or one-way kernel state on this machine.**
  Sysctls like `kernel.yama.ptrace_scope` are one-way per boot; a workflow
  agent that raised it latched this host until reboot (2026-09-01).
  Measurements that need kernel-global changes run in a disposable VM
  (`/dev/kvm` is available) or in CI. If shared host state is found mutated,
  surface it to the user immediately.
```

### Proposal 4 — ci.yml header addition (after the "three-line swap" block)

```markdown
# Before swapping labels, prove runner pickup with a canary: push a
# throwaway workflow whose only job is `runs-on: blacksmith-2vcpu-ubuntu-2404`
# + `run: echo ok`, and wait for green before migrating the real gate.
# (2026-08-31: the full gate was migrated first and queued — no runner ever
# matched until support allowlisted the org.)
```

## Questions for the user

- **Go for the VM lab (#6)?** You asked "can't we next time just create a
  small vm for testing?" and the agent answered with a build plan "if you
  say go" — the go never came before the session ended. Approve building
  `research/vm-lab/` and filing the ticket?
- **File #5 upstream?** The `[object Object]` coercion is a pi workflow
  runtime behavior, not a repo bug; fixing it here is impossible. OK to file
  it as an upstream issue, or keep mitigation doc-only?
- Unchanged reminder from the session: this host is **still** latched at
  yama `ptrace_scope=3` — it needs a reboot; no proposal can substitute.
