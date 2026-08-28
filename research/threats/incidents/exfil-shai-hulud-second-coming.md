# Shai-Hulud "Second Coming" wave bulk-uploaded harvested secrets to public GitHub repos

- Date: 2025-11-23 | Agent/tool: npm packages (Zapier and ENS ecosystem packages, GitHub Actions runners) | Axis: exfil

## What happened

On November 23, 2025 the Shai-Hulud npm worm returned as "Sha1-Hulud: The Second Coming". It is a second, separate wave from the September 2025 worm in this ledger (INC-003), with a much stronger exfiltration step. Malicious postinstall scripts harvested environment variables, GitHub tokens, npm tokens, and AWS/GCP/Azure secrets. They ran the TruffleHog scanner against the victim's home directory. The collected data was uploaded as JSON files to fresh public GitHub repositories described "Sha1-Hulud: The Second Coming". StepSecurity counted more than 22,000 malicious repositories. In CI, injected workflows dumped repository secrets to attacker-visible workflow artifacts and deleted themselves to hide the trail. Zapier and ENS domains packages were among the compromised ones.

## How it went wrong

A victim runs `npm install` for an infected package. The npm lifecycle hook starts `node`/`bun` (setup_bun.js, then bun_environment.js). That process runs TruffleHog over the home directory and caches the binary in `~/.truffler-cache/`. It reads `~/.npmrc`, `process.env`, and cloud secret managers when ambient credentials allow it. Then a `collectAndExfiltrate()` function uses the victim's own GitHub token to create public repositories and upload `system.json`, `environment.json`, `secrets.json`, `truffleSecrets.json`, and `npm.json` — the egress target is `api.github.com`, an entirely legitimate-looking host. On CI machines it writes a `discussion.yaml` workflow that registers the machine as a self-hosted runner, dumps repository secrets into workflow artifacts, and deletes the workflow afterwards. At the OS level the firewall would see: exec of node/bun under an npm install, reads of credential files, and HTTPS PUT/POST traffic to github.com from that same process tree.

## What the firewall should learn

The signal is the combination, not any single event: a package-manager lifecycle process tree (npm → node/bun → trufflehog) that reads credential files and then makes write-shaped HTTPS calls to a non-package-registry host. Rule ideas: (1) approval_required (or deny) for `exec` descendants of npm/pnpm/yarn/bun install scripts that connect to hosts other than the configured registries; (2) deny when the same ancestry shows `file_open` reads of `~/.npmrc`, `~/.ssh/*`, or cloud credential files followed by a `network_connect` to github.com or any external host; (3) deny writes to `.github/workflows/*.yaml` triggered by a package install, since that is worm persistence.

## Sources

- [StepSecurity: Sha1-Hulud: The Second Coming — Zapier, ENS Domains, and Other Prominent NPM Packages Compromised](https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised)
- [Wiz: Shai-Hulud 2.0 — Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42: "Shai-Hulud" Worm Compromises npm Ecosystem in Supply Chain Attack](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Zscaler: Shai-Hulud V2 Poses Risk To NPM Supply Chain](https://www.zscaler.com/blogs/security-research/shai-hulud-v2-poses-risk-npm-supply-chain)
