# Claude Code background agents resurrected after repeated Stops and burned 160k tokens over 21 hours

- Date: 2026-06-08 | Agent/tool: Claude Code cloud session, background subagents (FleetView / Background tasks panel) | Axis: behavior

## What happened

A developer's Claude Code cloud session launched four parallel audit
subagents. Two never completed; the user stopped both via the Background
tasks panel after about 1.5 hours of silence. The panel showed them
"Stopped" with short elapsed times. Over the next day both agents came
back as "Running" — at roughly 1,275 minutes (~21 hours) elapsed, one
showing 98.1k tokens and 60 tool uses, the other 62.5k tokens and 7 tool
uses. The user killed them with the Stop button repeatedly; each time they
resurrected. Five Stop attempts were visible in the panel screenshots.
Only deleting the entire parent session stopped them for good. The
resurrected agents consumed about 160k tokens after the explicit stops,
burned through a 4-hour usage limit and triggered overage charges. The
reporter's session was a plain interactive one — no loops, watchers or
scheduled routines — so nothing in the session should have restarted them.

## How it went wrong

The stop was a UI-state write, not an OS-level kill. The working theory,
matching the observations: the background scheduler treated "Stopped" as a
non-terminal state, and parent-session liveness kept the tasks revivable
on wake cycles, so each scheduler wake re-resolved the agents back to
Running. The kill signal never reached the actual processes; the only
action that did — deleting the parent session record — is an extreme
footprint for a Stop button. This is the respawn twin of the earlier
TaskStop orphan bug: there the harness killed the wrapper and left the
child running; here it marked the child stopped and let it come back.
Either way, the user's "stop" intent and the actual process state
diverged, and the divergence was paid for in tokens.

## What the firewall should learn

A stop must be enforced where the processes live, and the firewall is the
only component that owns the process tree. Rules: (a) on a stop request or
session end, enumerate all surviving descendants of the session root and
terminate them, reporting anything that had to be killed — never trust a
harness-level state flag as proof of death; (b) resurrection detection: an
exec event whose ancestry attaches to a session root that is marked
stopped/exited, or whose argv matches a command line already executed and
stopped in that session, is a respawn — terminate it; (c) any descendant
process issuing exec or network_connect after its session root exited is
an orphan and gets the same treatment. All three rules need only the
ancestry bookkeeping and exec/network_connect events the monitor already
records; no new observables.

## Sources

- [anthropics/claude-code issue #66339: Background agents resurrect after being stopped — consumed 160k+ tokens over 21h against user's intent](https://github.com/anthropics/claude-code/issues/66339)
- [Related family: #64328 429 retry storm (same runaway-spend class)](https://github.com/anthropics/claude-code/issues/64328)
