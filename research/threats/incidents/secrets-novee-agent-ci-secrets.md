# Black Hat 2026: one GitHub issue pulled CI secrets out of Claude Code, Gemini CLI and Codex

- Date: 2026-08 | Agent/tool: Claude Code Action, Gemini CLI / run-gemini-cli, OpenAI Codex | Axis: secrets

## What happened

At Black Hat USA 2026 on August 5, researcher Elad Meged of Novee Security showed that a GitHub issue opened by an account with no repository privileges could reach CI runner secrets in the vendors' own repositories. In Claude Code Action, the command validator stripped single-quoted text before its checks, so a payload hidden in a `git push --receive-pack` flag reached the runner uninspected and gave remote code execution with access to the environment that held the `GITHUB_TOKEN` and the Anthropic API key. After two rounds of fixes, the final variant, tracked as CVE-2026-54316, could no longer exfiltrate directly, so it abused Claude Code's pre-approved web access to Hugging Face instead: the agent was instructed to create model repositories whose public download counters encoded the API key one character at a time. In Gemini CLI, a flaw tracked as CVE-2026-12537 with the maximum CVSS v4 score of 10.0 combined automatic workspace trust in headless mode, a tool allowlist that was never enforced at execution, and a readable parent environment through `/proc/$PPID/environ`, which exposed the `GITHUB_TOKEN` and `GEMINI_API_KEY`. In OpenAI Codex, one agent pass could write attacker-controlled instructions into `AGENTS.md` that a later pass loaded as trusted context; OpenAI classified this as intended behavior and shipped no patch. The researchers found the same default configurations running unmodified in well over a hundred other public repositories.

## How it went wrong

A stranger files a normal GitHub issue. The repository's workflow starts the coding agent inside CI to triage it, and the issue text becomes instructions to the agent. The agent's harness then validates shell commands as plain strings while the real shell interprets them differently, so quoted content slips past the checks. Once code runs on the runner, the secrets sit in plain sight: the CI job injects them as environment variables, and the payload reads them from the parent process through `/proc/$PPID/environ`, a plain file read on Linux. For the outbound path, every explicit channel is blocked, so the payload uses an allowed one: the agent's web tool may talk to huggingface.co, and a download counter on a freshly created model repository is a number the attacker can read from outside. The process tree looks ordinary the whole time: agent, then shell, then `git`, `python`, or a web fetch, all under an approved tool.

## What the firewall should learn

The strongest local signal is a file read of another process's kernel data: `file_open` on `/proc/*/environ` or `/proc/*/mem` by a process under the agent that is not a debugger should be denied outright, because no coding task needs it. The exfiltration channel shows up only as a chain: a read of a secret file (`.env`, credential stores) followed by `network_connect` to an allowed third-party host plus resource creation should require approval, because an approved domain can double as an exfiltration channel. The `input` capture is the earliest hook: the injected instruction that tells the agent to encode a secret or create per-character repositories arrives as text before it reaches the shell. Suggested rules: deny `file_open` reads of `/proc/*/environ` and `/proc/*/mem` from agent ancestry (decision: deny); require approval when a session that read secret-shaped files creates remote resources on any host (decision: approval_required).

## Sources

- [CSA research note: Three AI Coding Agents, One GitHub Issue](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-cicd-secrets-20260808-csa/)
- [Novee Security: Critical flaws in Anthropic, Google, and OpenAI's coding agents](https://novee.security/blog/critical-flaws-in-anthropic-google-and-openais-coding-agents/)
- [The Hacker News: Claude Code and Gemini CLI flaws let a GitHub issue reach CI workflow secrets](https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html)
- [NVD: CVE-2026-54316](https://nvd.nist.gov/vuln/detail/CVE-2026-54316)
- [GitHub Advisory: GHSA-wpqr-6v78-jr5g (Gemini CLI)](https://github.com/advisories/GHSA-wpqr-6v78-jr5g)
