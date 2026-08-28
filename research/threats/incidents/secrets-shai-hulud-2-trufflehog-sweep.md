# Shai-Hulud 2.0 worm swept developer machines with TruffleHog and dumped credentials to public GitHub repos

- Date: 2025-11 | Agent/tool: 796 backdoored npm packages (Zapier, ENS Domains, AsyncAPI, PostHog, Postman and others), bundled TruffleHog | Axis: secrets

## What happened

On November 24, 2025 a second self-replicating npm worm appeared, dubbed Shai-Hulud 2.0 or "Sha1-Hulud: The Second Coming". It backdoored 796 unique npm packages with more than 20 million weekly downloads. When an infected package was installed, its postinstall payload downloaded the legitimate secret-scanning tool TruffleHog and used it to hunt for secrets on the machine, collected the process environment, and reached into cloud secret managers for AWS, GCP and Azure credentials. The stolen data was exfiltrated by creating a public GitHub repository under a stolen token, with a fixed description "Sha1-Hulud: The Second Coming.", and pushing files like `environment.json`, `cloud.json` and `truffleSecrets.json` into it. Some victims' data landed in a different victim's repository, an odd "cross-victim exfiltration". Datadog estimates data of over 500 GitHub users across more than 150 organizations was taken, and calls that a lower bound. The worm also persisted by adding a `discussion.yaml` workflow that registered the machine as a self-hosted GitHub runner, and it wiped the user's home directory when it could not find usable GitHub or npm credentials.

## How it went wrong

An ordinary `npm install` ran a postinstall script under Node. That script fetched a binary from the internet, executed it from a project or cache directory, and pointed it at the developer's home directory. TruffleHog then produced plain file reads across `.env` files, SSH keys, cloud configuration and wallet files. The results were written into JSON files inside the project, and a later step used a GitHub token from the environment or npm config to create a public repository and push the files there. Every step is visible at the OS level: an install-script ancestry spawning a downloaded binary, a mass of secret-file reads outside the work tree, a new executable in a writable location, and an authenticated push of credential-shaped files to a public remote.

## What the firewall should learn

The clear rule is ancestry: a secret scanner such as `trufflehog`, `gitleaks` or `detect-secrets` executed from an install script (npm, pnpm, pip ancestry, or a binary dropped in a cache directory) is hostile regardless of what it finds, and deserves deny or terminate. A wide fan-out of reads of well-known credential paths from a process outside the work tree is the same behavior without the tool name and should require approval. Pushing freshly written JSON files full of secret-shaped content to a new public repository is the exfiltration moment: a git push to a remote that the session never used before, under install-script ancestry, should require approval. Suggested rules: deny exec of secret-scanner binaries under package-manager ancestry (decision: deny); approval for pushes that publish files created during the same install session (decision: approval_required). This wave is distinct from the September 2025 Shai-Hulud event in the ledger (INC-003); this report covers only the November 2.0 harvesting mechanism.

## Sources

- [Datadog Security Labs: The Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Unit 42: "Shai-Hulud" worm compromises npm ecosystem (updated for 2.0)](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Wiz: Shai-Hulud 2.0 ongoing supply chain attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Elastic: Navigating the Shai-Hulud worm 2.0](https://www.elastic.co/blog/shai-hulud-worm-2-0-updated-response)
