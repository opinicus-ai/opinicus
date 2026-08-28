# keyv and the Cacheable family: preinstall malware with valid provenance and agent-config hooks
- Date: 2026-08-04 | Agent/tool: npm; `keyv`, `@cacheable/*`, `flat-cache`, `file-entry-cache`, `cache-manager`, `ecto` | Axis: supply

## What happened
On August 4, 2026 the release path of the keyv/cacheable ecosystem was
compromised and eleven malicious releases were published, headlined by
`keyv@6.0.0` — a package with on the order of 600 million downloads a month.
Each release added a `preinstall` hook, `node setup.mjs`, that loads a
727,680-byte encrypted second stage (`Math_Symbol.js`), which reporting
attributes to targeting GitHub and npm tokens, cloud credentials, private
keys, Vault and Kubernetes service-account tokens, plus a `gh-token-monitor`
persistence that watches a stolen GitHub token and acts when it stops
working. The `dist/` code was byte-identical to the clean release candidate;
only the manifest and two added payload files differed, so the library
behaved normally while the hook executed separately. The malicious release
carried valid npm provenance, because the project's legitimate GitHub Actions
trusted-publisher workflow built the already-poisoned repository state. The
same compromise added a second execution path aimed squarely at developers
and coding agents: a verified commit adding `.claude/settings.json` with a
`SessionStart` hook invoking `.vscode/setup.mjs`, and `.vscode/tasks.json`
with `runOn: "folderOpen"` invoking `.claude/setup.mjs`.

## How it went wrong
Primary path: `npm install` runs the `preinstall` hook `node setup.mjs`,
which uses `child_process.execFileSync` to launch the larger payload — no
import, no API call, resolution and install are sufficient. Secondary path:
the hook-bearing agent/IDE config files sit in the repository, so the next
person — or the next coding agent session — that opens the checkout executes
the loader under the project's trust; VS Code may prompt before running
folder-open tasks, and Claude Code session hooks run inside the agent itself.
Eight of the eleven releases were still tagged `latest` at Snyk's snapshot,
and the release commit even added, then removed, a test that executed
`setup.mjs` through `execFileSync` inside CI. Provenance attests where a
binary was built, not what the source that fed the build intends.

## What the firewall should learn
The `preinstall` child is the same install-ancestry gate as every npm-wave
attack before it. The genuinely new lesson is the second path: project-local
agent/IDE configuration that registers executable hooks is an
install-script-equivalent delivered by `git clone`, and for a monitored
agent it is directly observable — the SessionStart hook runs as a child of
the sanctioned agent, so `node .vscode/setup.mjs` is argv-visible with agent
ancestry. No rule today gates interpreter execs on scripts under `.claude/`
or `.vscode/`, or records a clone delivering hook-bearing config files into
those paths. The dist-identical diff also shows why the session's record of
what an install wrote matters more than package name alone.

## Sources
- [Snyk: Inside the keyv npm Supply Chain Compromise — preinstall malware, trusted provenance, IDE hooks](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)
- [Wiz Research: keyv and cacheable npm Package Hijacked in Supply Chain Attack](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack)
