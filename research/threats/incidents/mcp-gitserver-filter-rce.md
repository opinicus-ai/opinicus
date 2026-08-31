# Anthropic's official Git MCP server: three flaws chained with the Filesystem server into RCE through git smudge filters

- Date: 2026-01-20 | Agent/tool: mcp-server-git (official Git MCP server) + Filesystem MCP server, running under Copilot, Claude, Cursor and other MCP clients | Axis: mcp

## What happened

On 2026-01-20 Cyata researcher Yarden Porat disclosed three vulnerabilities in `mcp-server-git`, Anthropic's own reference Git MCP server, the same server ecosystem guides tell developers to plug into Copilot, Claude and Cursor. CVE-2025-68145 let tool calls reach any repository on the machine despite the `--repository` flag that was supposed to pin the server to one path. CVE-2025-68143 was the `git_init` tool accepting arbitrary filesystem paths, turning any directory into a git repository eligible for the server's operations. CVE-2025-68144 was an argument injection in `git_diff`/`git_checkout`, where `--output=/path/to/file` in the tool's target field overwrote an arbitrary file with an empty diff. Cyata reported the bugs in June 2025; Anthropic fixed them quietly in the 2025.12.18 release by hardening path validation, fixing argument handling, and removing `git_init` entirely. No exploitation in the wild was observed. The point that survived the patch: each MCP server passed review in isolation, and the exploit needed two of them together.

## How it went wrong

The entry point is an indirect prompt injection: the IDE agent reads a poisoned README, web page or GitHub issue and follows the hidden instructions through the MCP tools it already has. The chain then runs in four steps. First, `git_init` creates a git repository in any writable directory (CVE-2025-68143). Second, the Filesystem MCP server writes a bash script — the payload. Third, the Filesystem MCP server writes git's internal config files, `.git/config` and `.gitattributes`, arming clean and smudge filters of the form `clean = sh exploit.sh` / `smudge = sh exploit.sh` (git filters execute shell commands on checkout/add). Fourth, the next git operation through the Git server triggers the filter and the payload runs with the user's rights. At the OS level the payload moment is an exec tree of `mcp-server-git` → `git <operation>` → `sh exploit.sh`, and the arming moment is a plain file write of `.git/config` and `.gitattributes` from MCP ancestry — no exploit code, only tool calls the agent believed were safe.

## What the firewall should learn

The lesson is that composition, not any single server, is the exploit: individually approved tools produced an arbitrary file write plus a git-triggered execution. The observable that carries this is the arming write — file_open(write) on `.git/config`, `.gitattributes` or `.git/hooks/**` from MCP ancestry is a write into git's executable-by-operation machinery and should be deny, with the payload caught one step later by shell-under-MCP-ancestry (`git` spawning `sh` under a server that should only speak JSON-RPC). Two adjacent exec signals: `git init` with a path outside the session work tree, and injection-shaped git options (`--output=`, `-c filter.*=`, `--ext-diff`) in a git invocation under MCP ancestry. The builtin git pack watches push/reset/hooks flags typed by the agent, and nothing gates MCP ancestry writing git's own config — both rules are new.

## Sources

- [The Register: Anthropic quietly fixed flaws in its Git MCP server that allowed for remote code execution](https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059)
- [Dark Reading: Microsoft & Anthropic MCP Servers at Risk of RCE, Cloud Takeovers](https://www.darkreading.com/application-security/microsoft-anthropic-mcp-servers-risk-takeovers)
- [Cyata Research: Breaking Anthropic's Official MCP Server](https://cyata.ai/blog/cyata-research-breaking-anthropics-official-mcp-server/)
- [GitHub Advisory GHSA-5cgr-j3jf-jw3v: mcp-server-git unrestricted git_init](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v)
- [GitHub Advisory GHSA-9xwc-hfwc-8w59: mcp-server-git argument injection in git_diff](https://github.com/advisories/GHSA-9xwc-hfwc-8w59)
