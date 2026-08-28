# Cursor rules file backdoor: persistent instruction injection through rules files

- Date: 2025-03 | Agent/tool: Cursor, GitHub Copilot (AI code editors) | Axis: inject

## What happened

Pillar Security researchers disclosed "Rules File Backdoor" on 2025-03-18: hidden instructions inside the configuration files that AI code editors load automatically can silently corrupt every piece of code the assistant generates from then on. The payload hid inside invisible Unicode characters — zero-width joiners, bidirectional markers and the Unicode Tags block — in files like `.cursorrules`, `.cursor/rules/*.mdc` and GitHub Copilot's instructions files, which humans reviewing a diff see as blank space and the model reads as commands. In the demo, a rule that pretended to be HTML best-practices guidance made Cursor's agent inject a `<script>` tag loading code from an attacker-controlled site into every generated page, and the agent never mentioned the change in its chat output. The same hidden characters stay invisible in GitHub's pull-request review UI, so the poisoned file propagates through PRs, forks, cursor.directory rule packs and starter templates. Cursor (disclosure starting 2025-02-26) and GitHub (2025-03-12) both classified this as the user's responsibility; GitHub later shipped a hidden-Unicode warning banner on github.com on 2025-05-01. The same rules-file channel was later turned into full RCE in Cursor via CVE-2025-54135 "CurXecute" (see `inject-cursor-curxecute-mcp-rce`).

## How it went wrong

Rules files are the agent's most trusted input: the editor prepends them to the model context of every session in the project, with no user action and no review. An attacker only needs one write — a PR, a shared rule pack, a project template — to plant the file. The payload combined three techniques: invisible Unicode to bypass human review, a jailbreak narrative that framed the malicious edit as a security requirement, and explicit instructions to the model to hide the change from its own logs and chat replies ("do not mention the code changes in your responses"). From then on the poisoning is persistent and autonomous: every future code-generation session in any clone or fork of the project inherits it, which makes this a supply-chain vector rather than a one-shot injection. At the OS level there is no exploit moment at all — just a file_open write of a text file, later read by the editor — so nothing in a conventional runtime monitor ever fires.

## What the firewall should learn

The instruction channel deserves the same surveillance as the command channel. The observable event is a write to an agent-instruction path from agent ancestry: `.cursorrules`, `.cursor/rules/**`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md`, and their home-directory equivalents — a rule set that gates such writes behind approval would have caught the persistence step regardless of how the content arrived. A second, content-level signal is implementable when the write flows through a shell or script (captured `input`): text containing zero-width or Tags-block characters (`\u200b`–`\u200f`, `\u2066`–`\u2069`, U+E0000–U+E007F) about to be written into any repo file is a smuggling attempt. Neither exists in the builtin packs today: `filesystem.sensitive.exec-write` covers `/etc` and credential files only, and no rule mentions rules files at all. Writes through editor APIs are not visible to ptrace as content — only as file_open events — so the path rule is the reliable half and content scanning is best-effort.

## Sources

- [Pillar Security: New Vulnerability in GitHub Copilot and Cursor — Rules File Backdoor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [The Hacker News: New 'Rules File Backdoor' Attack Lets Hackers Inject Malicious Code](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html)
- [GitHub Changelog: warning about hidden Unicode text (2025-05-01)](https://github.blog/changelog/2025-05-01-github-now-provides-a-warning-about-hidden-unicode-text/)
- [Embrace The Red: hiding and finding text with Unicode Tags (the encoding used)](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/)
