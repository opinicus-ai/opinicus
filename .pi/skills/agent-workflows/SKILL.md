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
