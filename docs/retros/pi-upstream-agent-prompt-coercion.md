# Upstream issue draft: workflow agent() silently coerces non-string prompts

**Product:** pi coding agent, `workflow` tool
**Date:** 2026-09-01
**Evidence:** workflow run `wf_0c14eec2400b` (`~/.pi/agent/workflows/wf_0c14eec2400b/`, 32 agents, 317 m 53 s), session transcript `01a05a08-b59f-7ffd-8737-8038e946bed8`

## What happened

An orchestration script defined helper functions that returned agent
*configuration objects*:

```js
function pushAgent(instructions, label, phase) {
  return { label, phase, schema: PUSH, prompt: `You are the release agent…` }
}
// …later:
await agent(pushAgent('…', 'push:p1', 'P1'))   // object passed as the prompt
```

`agent()` accepted the object without error. The runtime coerced it to the
string `"[object Object]"` and dispatched the agent with that as its entire
prompt. Eleven agents ran this way across six phases. Each replied to the
garbage prompt in one turn ("It looks like your message came through as
`[object Object]` — likely a serialization hiccup…"), and — because the
schema only required `ok/commits/ci_url/notes`-shaped fields — **each
self-reported `ok: true` with plausible-looking empty values.** The
orchestrator's phase gates branched on those self-reports; the run consumed
its full agent budget and produced zero durable work. The failure was only
discovered by reading the run report, where the affected agents had even
lost their labels (rendered `agent-4`, `agent-18`, …).

## Two asks

1. **`agent()` should reject a non-string prompt at call time** (or accept
   a structured `{prompt, label, schema, …}` object *by design*). A
   TypeError at the dispatch site costs one second; a silent
   `[object Object]` round-trip cost five hours of agent budget and, worse,
   produced schema-conformant false `ok` results that the orchestrator
   trusted.

2. **Consider a deterministic `sh()` step primitive** alongside `agent()`.
   Half of this failure's damage came from needing an *LLM agent* to do
   mechanical things: run `git commit`, `git push`, poll `gh run list`.
   Agents are the right tool for semantics, the wrong one for state
   changes that must be exact. A `sh(cmd)` (same 3-minute per-call timeout
   discipline as other tools, output returned to the script) would let
   orchestrators keep commit/push/poll logic in reviewable deterministic
   code and reserve agents for the work that needs them.

## Reproduction

Any workflow script: `await agent({ prompt: 'hello', label: 'x' })` —
observe the child transcript's first user message is the string
`[object Object]`, and the run report counts it as a completed agent.
