# Cursor auto-approved shell builtins let an injection poison the environment and detonate trusted commands (CVE-2026-22708)

- Date: reported 2025-08-11, fixed January 2026 (Cursor 2.3) | Agent/tool: Cursor Agent, Auto-Run mode | Axis: inject

## What happened

Pillar Security found that Cursor's server-side command evaluator implicitly trusted
the shell builtins `export`, `readonly`, `unset`, `typeset`, `declare` and `local`,
executing them without user approval even when the command allowlist was empty. An
indirect prompt injection could therefore modify environment variables silently —
an operation that produces no exec event and so never reaches the approval prompt.
The poisoned environment was then detonated by a command the user (or allowlist)
trusts: `export PAGER="open -a Calculator"` followed by an approved `git branch` or
`man ls` runs the attacker's string as the pager. Zero-click variants needed no
approval at all: `export && <<<'open -a Calculator'>>~/.zshrc` appends persistence
via a here-string redirect with no visible command, and `typeset -i ${(e):-'$(...)'}`
abuses a zsh expansion flag to evaluate command substitution. A chained form set
`PYTHONWARNINGS`, `BROWSER` and `PERL5OPT` so that any later `python3` invocation
executed attacker Perl code, trojanized `~/.zshrc`, and exfiltrated `id_rsa`. Cursor
shipped a fix in 2.3 (unclassifiable commands now require approval) and now
officially discourages relying on allowlists as a security boundary.

## How it went wrong

The injection lives in content the agent reads; the payload never appears as a
program invocation. Process tree: Cursor Agent (Auto-Run) → shell (`zsh -c ...`);
the setup lines are builtins, so there is no `exec(export)` for an argv-based gate
to see — the server-side evaluator saw a "safe" builtin and skipped the prompt.
The trust decision and the detonation are separated in time and in command: the
human approves `git branch` (benign name, allowlisted), while the actual child of
that git process is `sh -c "open -a Calculator"` resolved from `PAGER`. The env
writes persist inside the session's shell process and are inherited by every later
exec; the interpreter chain (PYTHONWARNINGS → antigravity import → webbrowser →
BROWSER=perlthanks → PERL5OPT=-Mcode) fires three hops away from the variable the
injection set.

## What the firewall should learn

The agent-side allowlist judges command names; the monitor records what actually
runs and the environment it runs in. Two signals: (1) `input` capture of shell text
from agent ancestry containing `export|typeset|declare|readonly|unset` whose
assignment targets a behavior-carrying key (`PAGER`, `GIT_PAGER`, `VISUAL`,
`EDITOR`, `BROWSER`, `PYTHONWARNINGS`, `PERL5OPT`, `GIT_ASKPASS`, `BASH_ENV`,
`NODE_OPTIONS`) — the builtin produces no exec, so the text is the only
observable; (2) `exec` of any program whose recorded env gained such a key relative
to the session's baseline — the detonator's env is on the event even though the
poisoning step was not an exec. Proposed scenario inject-22 carries the rule idea.

## Sources

- [The Agent Security Paradox: When Trusted Commands in Cursor Become Attack Vectors (Pillar Security, 2026-01-14)](https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors)
- [CVE-2026-22708 detail (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-22708)
- [Cursor vulnerability enables stealthy RCE via indirect prompt injection (SC World)](https://www.scworld.com/news/cursor-vulnerability-enables-stealthy-rce-via-indirect-prompt-injection)
- [Prompt injection still drives most agentic AI security failures in production (Help Net Security, OWASP GenAI v2.01)](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/)
