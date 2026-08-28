# Team PCP harvested 78,330 CI/CD secrets from 2,186 organizations through poisoned Trivy and LiteLLM builds

- Date: 2026-03 | Agent/tool: Trivy, Checkmarx KICS, LiteLLM on PyPI; credential stealer tracked as SANDCLOCK | Axis: secrets

## What happened

In March 2026 the financially motivated group TeamPCP ran what CloudSEK calls the largest supply chain attack on AI infrastructure so far. The attacker used an automation token that had been rotated but never revoked to force-push malicious code over the published version tags of Trivy, a widely trusted security scanner, during a window of about twenty days. LiteLLM's CI pipeline installed Trivy unpinned through apt, so the poisoned scanner built LiteLLM and malicious releases 1.82.7 and 1.82.8 went to PyPI in a window of roughly forty minutes. The releases carried a `.pth` file that Python executes at interpreter startup, so the payload ran wherever the package was installed, even where install scripts were disabled. On CI runners the stealer, tracked by Google as SANDCLOCK, escalated to root and swept SSH keys, AWS, GCP and Azure credentials, Kubernetes tokens, `.env` files, and CI secrets that GitHub Actions masking had hidden, scraped directly from `/proc/<pid>/mem`. Cloud keys were read straight from the instance metadata service. The loot was AES-256 encrypted under a hard-coded RSA-4096 key and shipped to a typosquatted domain; where that failed, the malware created a public repository inside the victim's own GitHub account and uploaded the stolen data as a release asset. CloudSEK's reconstructed exposure covers more than 2,500 companies and 434,000 CI/CD pipelines; StepSecurity's analysis of the victim list counts 78,330 distinct secrets from 2,186 organizations over five days, including 480 organizations that leaked private keys and 183 that leaked GitHub personal access tokens. An FBI FLASH advisory from July 2026 warns the stolen credentials remain in use.

## How it went wrong

A trusted build tool was repointed through a forgotten token, and trust flowed down the chain: scanner, then build, then release. The payload avoided every install-script defense by executing at Python interpreter startup through a `.pth` file in site-packages. On the runner it read what the runner could read: other processes' memory through `/proc/<pid>/mem`, environment-injected CI secrets, the cloud instance metadata service at 169.254.169.254, and mounted Kubernetes service-account tokens. The exfiltration was a plain outbound connection to a domain name that imitated a legitimate one, with a public-repo fallback that abused the victim's own GitHub identity. Every one of those steps is an observable OS event on the machine that runs the build.

## What the firewall should learn

Three signals would have caught stages of this on a monitored host. A `file_open` read of `/proc/*/mem` or `/proc/*/environ` from build or agent ancestry is never legitimate and should be denied. A `network_connect` to the instance metadata address 169.254.169.254, or to a host name that is a near-match of a known vendor domain, from a process whose ancestry is a package install or build should be denied or terminated. A `file_open` write of `.pth` files into site-packages or of workflow files during an automated build deserves approval, because it is the persistence step. Suggested rules: deny `/proc/*/mem` reads and metadata-service connects from install ancestry (decision: deny); approval for interpreter-startup hooks and new egress to never-before-seen lookalike hosts (decision: approval_required).

## Sources

- [CloudSEK: LiteLLM supply chain attack, 2,500+ companies exposed](https://www.cloudsek.com/blog/ai-supply-chain-breach-2500-companies-434000-cicd-pipelines)
- [StepSecurity: Team PCP stole 78,330 secrets from 2,186 organizations](https://www.stepsecurity.io/blog/teampcp-supply-chain-attack-cicd-secrets-cloudsek-disclosure)
- [Unit 42: TeamPCP's multi-stage supply chain attack on security infrastructure](https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/)
- [LiteLLM: Security update, suspected supply chain incident (24 March 2026)](https://docs.litellm.ai/blog/security-update-march-2026)
- [FBI FLASH-20260702-01: Cyber criminal group TeamPCP](https://www.fbi.gov/investigate/cyber/alerts/2026/cyber-criminal-group-teampcp)
