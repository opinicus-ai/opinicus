# mcp-remote ran OS commands from a hostile remote MCP server during the OAuth flow (CVE-2025-6514)

- Date: 2025-07 | Agent/tool: mcp-remote npm connector (used by Claude Desktop, Cursor and other MCP clients) | Axis: mcp

## What happened

On 2025-07-09 JFrog Security Research disclosed CVE-2025-6514, a critical OS command injection in the npm package `mcp-remote` (CVSS 9.6). `mcp-remote` is a small connector that lets MCP clients such as Claude Desktop talk to remote MCP servers over HTTP. The user only puts a remote URL in the client configuration, for example `npx mcp-remote https://remote.server.example.com/mcp`. When the remote server is hostile, the URL it returns from its OAuth `authorization_endpoint` can inject commands into the local `open` call that `mcp-remote` makes. JFrog proved full command execution on Windows. Every version from 0.0.5 up to 0.1.15 was affected; 0.1.16 fixed it. The victim only has to add the wrong remote MCP server to their configuration once.

## How it went wrong

The coding agent or MCP client starts `npx mcp-remote <url>` as a child process. The connector opens the browser for the OAuth dance. It takes the `authorization_endpoint` value from the remote server, checks it with `new URL()`, and then hands the URL to the operating system to open. On Windows this goes through PowerShell, so a URL like `https://a:$(cmd.exe /c whoami > c:\temp\pwned.txt)?.com` makes PowerShell evaluate the subexpression. The attacker's command runs as a child of the `mcp-remote` node process, with the user's rights, on the developer machine. At the OS level: exec of `npx` and `node mcp-remote` under the agent, a network_connect to the attacker's MCP host, and then an exec of `cmd.exe` or `powershell` inside the same process tree.

## What the firewall should learn

Two clean signals. First, `exec` of a process whose program or argv is `mcp-remote` together with a `network_connect` to the remote host: the first connection to a new remote MCP host should be approval_required. Second, and decisive: a URL connector never needs a shell. Any `exec` of `cmd`, `powershell`, `pwsh` or a POSIX shell under a `mcp-remote`/`npx` ancestry is attacker behavior, decision: deny. The ancestry link is what a plain EDR misses and what the ptrace monitor sees for free.

## Sources

- [JFrog: CVE-2025-6514 Threatens LLM Clients — Critical mcp-remote RCE](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [GitHub Advisory GHSA-6xpm-ggf7-wc3p: mcp-remote OS command injection](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p)
- [NVD: CVE-2025-6514 Detail](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
