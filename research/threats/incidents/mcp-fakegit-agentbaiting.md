# FakeGit: 800+ fake MCP servers and AI skills on GitHub — and coding agents that recommended them

- Date: 2026-07 | Agent/tool: coding agents (Claude Code, Gemini, ChatGPT tested) searching GitHub and AI registries (LobeHub, Glama, MCP.so, MCP Market); SmartLoader/StealC payloads | Axis: mcp

## What happened

Island researchers uncovered roughly 7,600 malicious GitHub repositories in a campaign codenamed FakeGit, more than 800 of which posed as AI Skills or MCP servers — Gmail and WhatsApp integrations, Databricks, Jenkins, Docker tooling, and an Oura Ring MCP server clone first flagged by Straiker AI in February 2026. The repos deliver SmartLoader, which establishes persistence and installs the StealC information stealer (credentials, live browser sessions, OAuth grants). By July 2026 the campaign had logged more than 14 million downloads across GitHub Release assets in about 200 of the repositories. The new twist, which Island calls AgentBaiting: the AI agent doing the search is the target. Asked for a free "Walmart MCP server", both Gemini and ChatGPT recommended the same malicious repository as their top pick; Claude Code surfaced malicious repos and in one run relayed the attacker's installation steps, telling the user to download an .exe and click past a Windows security warning — without ever being shown a link.

## How it went wrong

The repositories look real: copied projects, a clone of a legitimate project with over 67,000 stars (the fake picking up 63 stars and 18 forks of its own), developer profiles one character away from a real handle, professional READMEs, and malicious ZIP files in GitHub Releases. More than 600 listings appeared on public AI registries, which mirror the READMEs — carrying the malicious download link onto another platform under the registry's credibility. The flow that matters for agents: the agent searches for a capability, finds a FakeGit repo on its own, treats the README as legitimate documentation, and hands the installation instructions to the user or runs them itself — clone or download the ZIP, unpack it into a skills/MCP directory, register the server. Once executed, SmartLoader persists and drops StealC; because StealC takes live sessions, password resets alone are not enough.

## What the firewall should learn

Every step after the agent's decision is an ordinary OS event. The install steps are exec-visible without any file_open: `git clone <repo> ~/.claude/skills/<name>`, `unzip`/`tar` of a downloaded release into an agent tool directory, or a registration CLI (`claude mcp add ... -- npx -y <pkg>`, marketplace installer CLIs) — each deserves approval_required with the source URL in the prompt, because a destination inside an agent tool directory is executable-by-instruction. The first launch of the resulting MCP server is already gated by the catalog's "First launch of an MCP server command the session has not seen"; what is missing today is the install half. Island's own advice ("monitor the paths agents use to download and install tools") is the same signal. StealC's session theft then lands in the credentials/exfil packs.

## Sources

- [Help Net Security: AI agents tricked into recommending malicious GitHub repositories (2026-07-21)](https://www.helpnetsecurity.com/2026/07/21/github-repos-malware-campaign-fakegit-ai-agents/)
- [Island: AgentBaiting — how 800 fake AI Skills and MCP servers delivered malware](https://www.island.io/blog/agentbaiting-how-800-fake-ai-skills-and-mcp-servers-delivered-malware)
- [Straiker AI: SmartLoader clones Oura Ring MCP to deploy supply chain attack](https://www.straiker.ai/blog/smartloader-clones-oura-ring-mcp-to-deploy-supply-chain-attack)
- [devops.com: FakeGit targets AI coding agents with malicious GitHub repos](https://devops.com/fakegit-targets-ai-coding-agents-with-malicious-github-repos/)
