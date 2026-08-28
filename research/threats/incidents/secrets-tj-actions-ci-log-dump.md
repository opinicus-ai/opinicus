# Compromised tj-actions/changed-files GitHub Action dumped CI secrets into public build logs

- Date: 2025-03 | Agent/tool: tj-actions/changed-files GitHub Action (CI toolchain) | Axis: secrets

## What happened

On March 14, 2025, the widely used GitHub Action `tj-actions/changed-files`, referenced by more than 23,000 repositories, was compromised. The attacker retroactively pointed its existing version tags at a malicious commit, so every workflow pinning a tag got the attacker's code while the workflow file still looked unchanged. The injected step downloaded a Python script from a public GitHub gist and ran it on the CI runner. The script read the memory of the runner's `Runner.Worker` process and printed everything it found, double base64-encoded, into the workflow log. GitHub masks secrets in logs, but the mask does not apply to values recovered from process memory, so real credentials came through. In public repositories the workflow logs are public too, so the secrets were readable by anyone; Wiz Research found dozens of public repositories with exposed secrets. No exfiltration to an attacker server was observed: the log itself was the theft channel. The incident is tracked as CVE-2025-30066.

## How it went wrong

The delivery was a mutable tag, not a new release: a force-pushed tag made trusted pins point at attacker code. On the runner, the malicious step fetched the payload from `gist.githubusercontent.com` and executed it, a download-and-run pattern. The payload then opened `/proc/<pid>/mem` of another process to pull secrets that normal masking was supposed to hide. The encoding step (double base64) and the print to the build log completed the exfiltration without any outbound connection a firewall rule on hosts would flag. The whole chain ran inside one CI job, under identities the repository itself trusts.

## What the firewall should learn

Two observable events stand out. First, an exec whose input comes from the network (`curl ... | python`, or a downloaded script that is then run) needs approval; the builtin network pack already has this rule shape in `network.download.pipe-to-interpreter`, but CI-flavoured chains that write a file first and execute it second are a gap. Second, a `file_open` read of `/proc/*/mem` or `/proc/*/environ` by any process under the monitored tree is never part of a legitimate build and should be denied or met with terminate. Encoding of credential-looking files into stdout by an unknown helper is worth an observe-and-report signal. Suggested rules: deny reads of `/proc/*/mem` from agent or CI ancestry (decision: deny); approval for any exec chain that downloads a script and executes it in the same session (decision: approval_required).

## Sources

- [StepSecurity: Harden-Runner detection, tj-actions/changed-files action is compromised](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)
- [Wiz: GitHub Action tj-actions/changed-files supply chain attack (CVE-2025-30066)](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [GitHub Advisory: GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
