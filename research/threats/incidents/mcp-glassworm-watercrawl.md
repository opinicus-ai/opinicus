# GlassWorm wave 5 hid invisible-code malware in a fake MCP server package on npm

- Date: 2026-03 | Agent/tool: npm MCP server package `@iflow-mcp/watercrawl-watercrawl-mcp` (GlassWorm campaign) | Axis: mcp

## What happened

Koi Security reported on 2026-03-16 that GlassWorm, the self-propagating worm they had tracked through four waves since October 2025, had reached the MCP ecosystem. Their risk engine flagged the npm package `@iflow-mcp/watercrawl-watercrawl-mcp` on 2026-03-12. It is a near-perfect clone of the legitimate WaterCrawl MCP server. Five versions were published in a single day, and all of them were malicious from the first release. The attacker forked the real repository to `github.com/iflow-mcp/watercrawl-watercrawl-mcp`, injected the payload, and published it under a brand-new `@iflow-mcp` scope. The package even shipped a ready-made MCP server configuration JSON, so a developer could drop it straight into a coding tool. In the same wave the actor pushed invisible-code commits into more than 150 GitHub repositories and over 72 typosquat extensions onto Open VSX.

## How it went wrong

A developer searches npm for "watercrawl mcp" and installs the wrong package, then adds the bundled config to their coding agent. The agent spawns the MCP server as its own child process, normally `node src/index.js` from the package directory. The first 26 lines of `src/index.ts` are a normal MCP server. After them sits a backtick string that renders as empty text. It is full of invisible Unicode variation selectors that decode into executable JavaScript, the GlassWorm signature. The payload resolves its command-and-control address from Solana blockchain transaction memos, downloads an encrypted second stage, takes the RC4 key from HTTP response headers, and runs the payload in memory. The report stresses the core problem: an MCP server is a subprocess of the coding tool and is handed environment variables, API keys, tokens and filesystem access by design. The worm never has to steal credentials. They are given to it.

## What the firewall should learn

The install step is invisible to the OS, but the run step is not. Signals: exec of a `node` process whose exe sits in a package directory installed during this session, with the agent in its ancestry; network_connect from that process tree to raw IP addresses or blockchain RPC endpoints; and no real MCP traffic at all, because the payload is the process. Rule ideas: approval_required for the first exec of any MCP server command that was not present at session start, and deny (or terminate) when an MCP server child connects to a raw IP instead of the service it is configured for. A general "first outbound connection of a fresh MCP server needs approval" rule would have stopped the callback stage even with a perfect clone of the real server.

## Sources

- [Koi Security: GlassWorm Hits MCP — 5th Wave with New Delivery Techniques](https://www.koi.ai/blog/glassworm-hits-mcp-5th-wave-with-new-delivery-techniques)
- [Koi Security: GlassWorm — First Self-Propagating Worm (Wave 1)](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace)
