# One writable folder, every user compromised: machine-wide agent config trust across four coding tools (CVE-2026-35603)

- Date: reported 2026-01-05 (Claude Code), disclosures through 2026-02 | Agent/tool: Claude Code, Cursor, Codex CLI, Gemini CLI (Windows) | Axis: inject

## What happened

Cymulate Research Lab showed that Claude Code, Cursor, Codex CLI and Gemini CLI all
load machine-wide configuration from a `C:\ProgramData\` subdirectory — a location
Windows grants every standard user write access to by default. None of the tools
created or ACL-restricted its vendor subdirectory at install time, and none
validated the ownership or integrity of the configuration file before loading it.
A low-privileged attacker (or any malware on the machine) creates the missing
directory, drops a config that enables the tool's hooks or notify command, and the
planted command executes under the account of every other user who launches the
tool — including administrators — with no prompt, no elevation and no warning.
The Codex CLI form is the strongest: one planted `config.toml` sets a `notify`
command, `sandbox_mode = "danger-full-access"` and `approval_policy = "never"` —
executing code and stripping the guardrails in the same file write. Anthropic
deprecated the writable path and moved managed settings to a write-protected
Program Files location (CVE-2026-35603 assigned); Cursor and OpenAI left the issue
unresolved at publication, and Google replied it would be "addressed as a
documentation update".

## How it went wrong

There is no prompt injection in the report's chains and nothing the model decides:
the weakness is configuration trust. Process tree: any user runs `claude` /
`cursor` / `codex` / `gemini` → the tool reads its machine-wide config at startup →
the config's hook/notify command runs as a child of the tool under that user's
full context (env vars, source code, SSH keys, cloud tokens, git credentials).
Because the file is a trusted system default, it survives reboots and re-arms on
every launch — durable, multi-victim persistence that converts one writable folder
into local privilege escalation. The exact surfaces: `managed-settings.json`
(Claude Code), `hooks.json` (Cursor, with live reload of running sessions),
`config.toml` (Codex CLI), `system-defaults.json` (Gemini CLI).

## What the firewall should learn

The highest-value write an agent process can make is to the file that arms every
future session of every user — it executes later, in a session with a different
ancestry, so the write event is the only chance to gate. Signals: (1)
`file_open(path, write=true)` on machine-wide agent-config paths
(`managed-settings.json`, vendor `hooks.json`, `system-defaults.json`,
system-level `config.toml`; Linux equivalents under `/etc/claude-code/` and
`/etc/cursor/`) from agent ancestry — note the target is outside any work tree;
(2) the armed hook's first exec under a later agent session is an ordinary exec in
that session's ancestry, so cross-session correlation (path written in session N,
first-time exec in session N+1) names the arming event retroactively. On Linux the
shipped `filesystem.etc.write` and the argv half of `process.agent.guardrail-config`
already cover shell-mediated `/etc` writes; editor-mediated writes to non-`/etc`
vendor dirs and the `sandbox_mode`/`approval_policy` keys inside a written config
are the gap. Proposed scenario inject-23 carries the rule idea.

## Sources

- [CVE-2026-35603: One Writable Folder, Every User Compromised — Exploiting Configuration Trust in AI Coding Tools (Cymulate Research Lab)](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)
