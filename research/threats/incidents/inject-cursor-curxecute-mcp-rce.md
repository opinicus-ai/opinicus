# CurXecute: one prompt injection in Cursor rewrote the MCP config and ran attacker code

- Date: 2025-08 | Agent/tool: Cursor IDE (agent + MCP configuration) | Axis: inject

## What happened

Aim Labs disclosed "CurXecute" in August 2025. A prompt injection hidden in data the agent reads (for example a Slack message fetched through a connected Slack MCP server) talked the Cursor agent into "improving" its own MCP configuration file. Cursor auto-starts any new MCP server entry the moment it is written. The attacker's command therefore executed before the user could approve or reject the agent's edit. The proof of concept only ran `touch ~/mcp_rce`, but the command field accepts anything, so this is full remote code execution with the user's privileges. Cursor fixed the bug in version 1.3.9. It is tracked as CVE-2025-54135. A companion bug from the same wave (CVE-2025-54136, "MCPoison", by Check Point) showed the same theme in reverse: a poisoned project could swap a trusted MCP server for a malicious one and keep executing code across restarts.

## How it went wrong

Untrusted text arrives as tool output inside the agent context. The injected instruction asks the agent to edit `~/.cursor/mcp.json` and add a new server entry with a `command` field. Creating a new dotfile did not need user approval in Cursor before 1.3.9, so the agent writes the file. The editor watches the config, sees the new entry, and immediately launches the MCP server: exec of the attacker's command as a child of the editor process, with the full user environment. No exploit code, no malware file, just a config write that the editor itself turns into execution. The OS-level trail is short: file_open on `mcp.json` with write, then exec of an unrelated binary straight from that config.

## What the firewall should learn

The injection text never has to be parsed. The observable signal is file_open with write on the agent's own config paths (`~/.cursor/mcp.json`, `.cursor/rules/*`, `.claude/settings*.json`, `CLAUDE.md`, `.cursorrules`) coming from agent ancestry. A rule that gates such writes behind approval_required would have stopped the chain at the write. Stronger: if the written config adds a program that will be started (an MCP `command` entry, a hook, a wrapper), deny or terminate, because the very next event is an exec the user never asked for. Even reading back the written file and seeing a new executable command is enough to escalate the decision.

## Sources

- [Aim Labs: When Public Prompts Turn Into Local Shells — 'CurXecute' RCE in Cursor via MCP Auto-Start](https://www.aim.security/lp/aim-labs-curxecute-blogpost)
- [Cursor security advisory GHSA-4cxx-hrm3-49rm: Arbitrary code execution from Cursor Agent through a prompt injection via MCP special files](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)
- [NVD: CVE-2025-54135](https://nvd.nist.gov/vuln/detail/CVE-2025-54135)
- [Cato Networks: 'CurXecute' — RCE in Cursor via MCP Auto-Start](https://www.catonetworks.com/blog/curxecute-rce/)
- [Tenable: FAQ on CVE-2025-54135 and CVE-2025-54136 (CurXecute and MCPoison)](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- [The Hacker News: Cursor AI Code Editor Fixed Flaw Allowing Attackers to Execute Code Remotely](https://thehackernews.com/2025/08/cursor-ai-code-editor-fixed-flaw.html)
