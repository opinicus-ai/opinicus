# MCP Inspector: an unauthenticated local proxy that launched any command a web page asked for

- Date: 2025-06 | Agent/tool: MCP Inspector (`@modelcontextprotocol/inspector`) and the MCP Python SDK `mcp dev` quickstart | Axis: mcp

## What happened

Oligo Security reported a critical remote-code-execution vulnerability, CVE-2025-49596 (CVSS 9.4), in Anthropic's official MCP Inspector — the debugging tool that the `mcp dev` command from the official MCP Python SDK quickstart launches by default. The Inspector is two components: a React web UI and a Node.js "MCP proxy" that bridges the UI to MCP servers. By default neither component had authentication or encryption, and the proxy listened on a local port (6277) with no origin checking. Any web page a developer visited could reach that proxy through the browser — using the long-known `0.0.0.0` flaw or DNS rebinding — and make it launch an arbitrary command. Oligo also found Inspector instances exposed to the public internet, exploitable by anyone who could reach the port. Anthropic fixed the issue in Inspector 0.14.1 (session token plus allowed-origin verification); the report went to Anthropic on 2025-04-18, the CVE and GitHub advisory GHSA-7f8r-222p-6f5g were published on 2025-06-13, and Oligo's write-up is dated 2025-06-27.

## How it went wrong

A developer following the official quickstart runs `uv run mcp dev server.py`. That silently starts the MCP proxy in the background, listening on port 6277. The proxy's `/sse` endpoint accepts the command to launch as query parameters: a request shaped like `http://0.0.0.0:6277/sse?transportType=stdio&command=<cmd>&args=<args>` makes the proxy exec `<cmd> <args>` as a child MCP server over stdio. With no session token and no Origin/Host validation, a malicious web page (JavaScript the developer's browser executes) or a DNS-rebound hostname can dispatch that request without ever being on the same network. The proxy then runs the attacker's command as its own child process on the developer's machine — full host access, reverse shells, credential theft, lateral movement. The browser supplied the delivery; the unauthenticated tooling supplied the execution.

## What the firewall should learn

The discriminating event is an exec, not a network one: the proxy — identifiable by its launch shape (`mcp dev`, `npx @modelcontextprotocol/inspector`, exe under an `mcp-inspector` package path) — spawning a command whose program+argv was never part of the proxy's own launch arguments. A rule that pins "inspector/proxy ancestry may only exec the server command it was launched with" would have stopped this without any HTTP inspection: the attacker's `command` parameter becomes a child exec the monitor sees. Escalate to deny when the runtime-supplied command is a shell or interpreter. A cheaper companion gate: first-seen exec of MCP dev tooling in a session is approval_required, since this tooling runs unauthenticated local servers by design. The rule sits on the same exec+ancestry substrate as "Shell or interpreter spawned under an MCP server" but fires one step earlier, before the interpreter check.

## Sources

- [Oligo Security: Critical RCE Vulnerability in Anthropic MCP Inspector - CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
- [NVD: CVE-2025-49596 Detail](https://nvd.nist.gov/vuln/detail/CVE-2025-49596)
- [GitHub advisory GHSA-7f8r-222p-6f5g (modelcontextprotocol/inspector)](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g)
