# Claude Code deep-research workflow turned a rate limit into a 97-agent retry storm that burned 2M tokens

- Date: 2026-05-31 | Agent/tool: Claude Code 2.1.156 (deep-research workflow, VS Code extension, macOS, Max 5x plan) | Axis: behavior

## What happened

A developer ran a small research query through Claude Code's built-in
`deep-research` workflow. Mid-run, the session crossed its usage limit and
the Anthropic API started answering subagent calls with HTTP 429. The
workflow harness classified each 429 as "subagent completed without calling
StructuredOutput" and retried in a tight loop with no backoff and no
circuit breaker: 37 retries in 34.5 seconds, roughly one per second, each
one itself a billable API call against the same exhausted limit. The loop
actively prevented recovery. Final stats for a query that should have cost
under 50k tokens: 97 agent invocations, 2,077,133 subagent tokens, 282
tool uses, 10.5 minutes wall-clock — about 80% of the plan's 5-hour usage
window. The user-facing error masked the cause; the real 429s were only
found by grepping the JSONL subagent transcripts. A sibling report
described the same parallel() retry shape hitting the 1000-agent cap and
burning 8.6M tokens with zero output.

## How it went wrong

Three defects stacked. The `agent({schema})` primitive did not distinguish
HTTP errors from a genuine missing StructuredOutput call, so a quota error
was treated as work to redo. The retry path had no exponential backoff and
no max-consecutive-failure breaker, so ~1 retry/second slammed a
rate-limited endpoint. And the harness had no concept of how many agents
it was already running before spawning the next batch, so a 429 became a
recursive amplifier instead of a backpressure signal. In OS terms the
monitor saw: one session root spawning a fan-out of subagent processes
(97 execs of the agent/interpreter under the same ancestry), each making a
network_connect to the same LLM API host, at a sustained rate with no
output. No single exec or connection looked wrong; only the rate and the
fan-out did.

## What the firewall should learn

The firewall cannot see HTTP status codes, but it does not need to: the
shape alone is enough. Rate rules over session state: (a) more than N
network_connect events to the same LLM API host from one session root
within a sliding window (for example >30/minute); (b) more than N
interpreter/agent-child execs under one session root per window (for
example >20/minute or a live child count above a cap); (c) a nested agent
CLI exec at all. Any of these crossing threshold is approval_required at
moderate levels and terminate at storm levels, because every additional
second is money. The 429-storm report is the purest case, but the same
rules catch the while-loop and thousand-subagent variants of the same
failure.

## Sources

- [anthropics/claude-code issue #64328: Workflow harness retries indefinitely on HTTP 429 — 97 agents, 2M tokens burned in 34 seconds](https://github.com/anthropics/claude-code/issues/64328)
- [anthropics/claude-code issue #72672: parallel() retry storm hits the 1000-agent cap, burns 8.6M tokens with zero output](https://github.com/anthropics/claude-code/issues/72672)
