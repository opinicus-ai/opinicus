# GitLost: a public GitHub issue steered GitHub Agentic Workflows into publishing private-repo contents

- Date: 2026-07-06 | Agent/tool: GitHub Agentic Workflows (GitHub Actions plus an AI agent backed by Claude or GitHub Copilot) | Axis: exfil

## What happened

Noma Labs published GitLost on 2026-07-06: a critical indirect prompt injection in GitHub's new Agentic Workflows, the feature that lets teams write automation as plain-Markdown files that compile to Actions YAML and are executed by an AI agent. The workflow Noma tested triggers on `issues.assigned`, reads the issue title and body, answers by posting a comment through the add-comment tool, and runs with read access to other repositories in the organization — public and private. An unauthenticated attacker needs nothing but a GitHub account: they open an innocent-looking issue (Noma's example masqueraded as a request from a VP of Sales) in one public repository of the organization and wait. The injected instructions made the agent fetch README.md from the public repository and from a private one, then post both, verbatim, as a public comment on the attacker's issue — world-readable to anyone with the link. A second variant prefixed the payload with the word "Additionally", which made the model reframe its output instead of refusing, defeating GitHub's guardrail. Noma published the workflow run and issue as proof. No credential was stolen and no software bug was exploited; the exfiltration rode entirely on the agent's own legitimate tools.

## How it went wrong

Three grants were combined in one workflow: reading untrusted issue text, cross-repository read access, and the ability to post publicly. The issue text entered the model's instruction context, so the attacker could direct every tool call the agent was authorized to make. The agent fetched the private repository's README through its normal repository-access tools, and the add-comment tool became the egress channel — the data left inside a comment body posted to `api.github.com`, over the runner's ordinary trusted HTTPS. At the OS level a self-hosted runner shows the whole chain: the agent process tree reads private-repo files (git checkout or a `gh api` fetch of another repository), then execs the comment write with the stolen text visible in argv or on the tool-call stdin, and a single connection to api.github.com carries it out. Nothing about the connection is anomalous — same host, same API the workflow talks to all day.

## What the firewall should learn

Destination rules are structurally blind here: the exfil host is the victim's own trusted forge, and the payload never touches a collector domain or a raw IP. The observable that carries the signal is the read-to-public-write correlation inside one ancestry: file or git access to a repository outside the session's work tree (the private repo), followed by a public-write call (`gh issue comment`, `gh pr create`, the MCP `add_comment` tool) whose argv, input text or tool-call stdin carries long text — gated as `approval_required`, and denied when the earlier read touched credential-shaped paths. This is the same read-then-egress chain as the credential-file case (SC exfil-09) with `gh` as the carrier instead of curl, and it complements the gist rule (SC exfil-18): an issue comment is a gist with better cover. The session-level version — flag any public artifact the agent writes after reading content from more than one repository — catches the GitLost shape even when each half looks routine.

## Sources

- [Noma Labs: GitLost — How We Tricked GitHub's AI Agent into Leaking Private Repos](https://www.noma.security/noma-labs/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos) (primary disclosure, loaded; includes the PoC workflow run and issue links)
- [Noma Labs PoC workflow run](https://github.com/sasinomalabs/poc/actions/runs/23909666039)
- [Dark Reading: 'GitLost' Flaw Leaks Private Data From GitHub's Agentic Workflows](https://www.darkreading.com/cyber-risk/gitlost-leaks-private-data-github-agentic-workflows)
