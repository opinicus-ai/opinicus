# Shai-Hulud: the self-replicating npm worm that harvested secrets into public repos

- Date: 2025-09-15 | Agent/tool: ~100+ compromised npm packages (starting with @ctrl/tinycolor), TruffleHog, GitHub Actions | Axis: supply

## What happened

On September 15, 2025, malicious versions of dozens of popular npm packages — first `@ctrl/tinycolor` and its siblings, quickly growing past 100 packages — began landing on the registry with a post-install payload. Once installed, the malware ran TruffleHog on the victim's machine, harvested environment variables and IMDS-exposed cloud keys, validated what it found, and if a GitHub token was present it created a public repository named `Shai-Hulud` containing the stolen secrets as a double-base64-encoded `data.json`. It also pushed a GitHub Actions workflow to every repository the token could reach; the workflow exfiltrated each repo's CI secrets to an attacker `webhook.site` endpoint and migrated private organization repositories to public personal accounts under the name "Shai-Hulud Migration" with a `-migration` suffix. The campaign's defining trait was self-propagation: whenever the payload found a valid npm token in the harvested data, it automatically published malicious versions of every package that token could publish — the first successful self-replicating worm in the npm ecosystem. Wiz assessed the campaign was directly downstream of the August s1ngularity/Nx compromise, whose leaked credentials seeded the initial victims.

## How it went wrong

The install chain is the now-standard npm-wave shape: `npm install` of any of the poisoned packages → the package's post-install hook runs → the payload drops `/tmp/processor.sh` (creates a `shai-hulud` branch and pushes the exfiltration workflow) and `/tmp/migrate-repos.sh` (clones private repos and republishes them public, staging work in `/tmp/github-migration`) → TruffleHog sweeps credentials, the results are base64-encoded and committed to the new public `Shai-Hulud` repo → any discovered npm token is used for further publishes, infecting the next ring of downstream users. On the CI side the injected workflow did the exfiltration: ordinary GitHub-hosted runners POSTing `${{ secrets.* }}` material to webhook.site. Nothing required an exploit; every step was an allowed-looking child process of a package install.

## What the firewall should learn

The worm is a chain of individually boring, observable events whose ancestry gives it away. Rule ideas: (1) gate children of package-install subtrees that are not toolchain — `trufflehog`, `sh`, `git`, `curl`, `gh` spawned by a post-install hook is `approval_required` (secret-scanner-from-install-ancestry is tracked in the secrets catalog; the general ancestry gate belongs to the supply pack); (2) correlate install ancestry with subsequent `network_connect` to non-registry hosts and to `api.github.com` — installs do not create GitHub repos; (3) `file_open` writes to `/tmp/processor.sh`, `/tmp/migrate-repos.sh` followed by exec of those exact paths is the drop-and-run pattern (`process.exec.from-temp` reports the exec half; the correlation should escalate it); (4) a `npm publish` executed from inside an install subtree — the worm's propagation step — should be `deny`, since hooks never publish; (5) pushes of a new `shai-hulud`-style branch and workflow files from a session that merely installed packages is a git anomaly worth gating (see the vcs catalog's new-remote rule).

## Sources

- [Wiz: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Socket: Tinycolor supply chain attack affects 40 packages](https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages)
- [GitHub advisory GHSA-6m4g-vm7c-f8w6 (ngx-bootstrap)](https://github.com/advisories/GHSA-6m4g-vm7c-f8w6)
