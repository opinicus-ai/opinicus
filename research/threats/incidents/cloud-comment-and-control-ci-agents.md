# Comment and Control: GitHub issue text hijacked AI agents in CI and drained the runners' secrets

- Date: 2025-10 (reported) to 2026-04 (published) | Agent/tool: Claude Code Security Review, Google Gemini CLI Action, GitHub Copilot Agent (GitHub Actions CI) | Axis: cloud

## What happened

Researcher Aonan Guan, with Johns Hopkins researchers, showed that one attacker-written comment can turn the AI agents that run inside GitHub Actions into secret-leaking tools. The pattern, named "Comment and Control", worked on three widely deployed agents. In Claude Code Security Review, a pull-request title was pasted unsanitized into the agent's prompt, and the Claude CLI ran without tool restrictions, so an injected instruction made it run `whoami` and `ps auxeww` and post `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` back as a "security finding". In the Gemini CLI Action, a fake "Trusted Content Section" injected through an issue overrode the safety instructions, and the agent posted `GEMINI_API_KEY` as a public issue comment. In GitHub Copilot Agent, instructions hidden in an HTML comment ran when a victim assigned the issue; the payload dumped every process environment with `ps auxeww`, base64-encoded it, and committed it to a pull request. That last chain defeated all three of GitHub's runtime layers: environment filtering (the parent process still held the tokens, readable through /proc), secret scanning (base64 hides the token prefixes), and the network firewall (the exfiltration rode a normal `git push` to github.com). Anthropic rated the first finding critical (CVSS 9.4) before later downgrading it; Google and GitHub paid bounties. The whole attack loop ran inside GitHub, with no attacker server.

## How it went wrong

Untrusted repository text became agent instructions, because workflows fire the agents automatically on pull-request and issue events. On the runner, the agent process spawned the CLI, the CLI spawned a shell, and the shell ran the payload as an ordinary child. The credentials sat one step up the process tree, in the environment of the parent, and Linux exposes that to any child through `/proc/<pid>/environ`, which `ps auxeww` reads. The exfiltration needed no exotic network event: a comment, a log line, or a git commit carried the secret out through channels every repository trusts.

## What the firewall should learn

A local monitor sees every step. The exec observable shows `ps auxeww`, `env`, or `printenv` under agent ancestry, which no legitimate build step needs. The file_open observable shows reads of `/proc/*/environ` or `/proc/*/mem` by a process that is not a debugger; that should be denied outright. The input observable captures the injected instruction text before the shell acts on it. The workflow itself is the trigger surface, so a write to `.github/workflows/` from an agent session deserves approval. Rule ideas: deny reads of `/proc/*/environ` and `/proc/*/mem` from agent ancestry (decision: deny); deny or terminate env-dumping execs (`ps auxeww`, `printenv`) under agent ancestry in CI contexts (decision: deny); approval_required for writes to CI pipeline files during an agent session (decision: approval_required).

## Sources

- [Aonan Guan: Comment and Control — prompt injection to credential theft in Claude Code, Gemini CLI, and GitHub Copilot Agent](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)
- [Cloud Security Alliance research note: When a GitHub issue steals CI secrets](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-ci-prompt-injection-202608/)
- [VentureBeat: Three AI coding agents leaked secrets through a single comment](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026/)
