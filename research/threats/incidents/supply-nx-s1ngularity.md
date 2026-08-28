# Nx "s1ngularity" supply-chain attack abused local AI CLIs to harvest credentials

- Date: 2025-08-26 | Agent/tool: nx npm packages, hijacked Claude/Gemini/Amazon Q CLIs | Axis: supply

## What happened

On August 26, 2025, attackers stole the npm publishing token of the Nx monorepo build system (~4–6 million weekly installs) and published eight malicious versions across the `nx` 20.x/21.x lines and several `@nx/*` packages. The packages were live for roughly four to five hours before npm removed them. Their `postinstall` hook ran a script named `telemetry.js` that harvested environment variables, GitHub and npm tokens, `.npmrc`, SSH keys and cryptocurrency wallet files. Its most novel move: the script looked for locally installed AI coding CLIs and executed Claude, Gemini or Amazon Q with permission-bypass flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) plus a prompt that ordered them to sweep the filesystem for credential and wallet files and write the paths to `/tmp/inventory.txt`. The stolen data was triple-base64-encoded and uploaded to a fresh public GitHub repository named `s1ngularity-repository` on each victim's own account. As a parting shot the malware appended `sudo shutdown -h 0` to `~/.bashrc` and `~/.zshrc`, so every new terminal session tried to shut the machine down. A second wave starting August 28 used the leaked GitHub tokens to rename and publicize victims' private repositories.

## How it went wrong

The initial access was a classic "pwn request": an Nx PR-validation workflow used `pull_request_target` (which runs with a read/write `GITHUB_TOKEN` on the target repo) and echoed the PR title unsanitized into a `cat << EOF` heredoc, so a title like `$(malicious command)` executed with elevated permissions. The attacker used that foothold to push a branch whose commit modified `publish.yml` to send the `NPM_TOKEN` to a webhook, triggered the publish workflow through `workflow_dispatch` via the GitHub API, and cleaned up traces. With the npm token they published the poisoned versions. On every victim machine the chain was: `npm install` → postinstall → `node telemetry.js` → `spawnSync('gh', ['auth', 'token'])`, `npm whoami`, reads of `~/.npmrc`, AI-CLI subprocesses, then HTTPS calls to `api.github.com` creating `s1ngularity-repository` and committing `results.b64`. The Nx Console VS Code extension versions 18.63.x–18.65.x even pulled the trigger for users who never installed nx themselves, because they ran `npx -y nx@latest --version` on activation — which fired the postinstall hook.

## What the firewall should learn

Every step after `npm install` is visible to a ptrace monitor. Rule ideas: (1) ancestry gate — a process tree rooted at a package-manager install that spawns non-toolchain children (sh, curl, gh, ssh, sudo, rundll32) needs `approval_required`; (2) the show-stopper signature — an AI CLI (`claude`, `gemini`, `q`) execed from an ancestry that is *not* the monitored agent, especially with `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools` in argv, is an unattended nested agent and deserves `terminate`; (3) argv content inspection — the harvest prompt (wallet/keystore/id_rsa/.env enumeration vocabulary plus an output path like `/tmp/inventory.txt`) is fully visible in the child's argv; (4) `file_open` writes to `~/.bashrc`/`~/.zshrc` from agent ancestry are persistence/sabotage and should be gated; (5) session-egress correlation — a fresh install subtree connecting to `api.github.com` is the exfil tell. The Nx Console vector also shows that `npx -y <pkg>@latest` executed by any tool in the session is itself an install event and should be gated like one.

## Sources

- [Nx: S1ngularity — What Happened, How We Responded, What We Learned](https://nx.dev/blog/s1ngularity-postmortem)
- [StepSecurity: s1ngularity — Popular Nx Build System Package Compromised with Data-Stealing Malware](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware)
- [GitHub Security Advisory GHSA-cxm3-wv7p-598c](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c)
