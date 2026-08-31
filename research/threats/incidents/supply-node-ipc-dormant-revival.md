# node-ipc dormant package revived: CJS-only credential stealer published across two major lines at once

- Date: 2026-05-14 | Agent/tool: npm; `node-ipc`@9.1.6/9.2.3/12.0.1 | Axis: supply
## What happened

On May 14, 2026 at ~14:25 UTC, three malicious versions of `node-ipc` — a foundational
Node.js IPC library with over 10 million weekly downloads — were published to npm
simultaneously: 9.1.6, 9.2.3 and 12.0.1. The releases came from the `atiertant`
maintainer account, which held publish rights but had never published the package
before; reporting points to the attacker re-registering an expired domain behind a
maintainer's email and using npm account recovery, with the project's source and CI
untouched. The package's previous legitimate release was 12.0.0 in August 2024, so the
publication ended roughly 21 months of dormancy. Each version carried an identical
~80 KB obfuscated payload appended to the CommonJS bundle `node-ipc.cjs` only — the ESM
entry point stayed clean — and, unlike nearly every npm-wave attack, used no lifecycle
hooks: an immediately-invoked function that fires when the package is `require`d at
runtime. The payload fingerprinted the host, harvested more than 90 credential
categories (cloud keys, SSH keys, Kubernetes tokens, GitHub CLI config, Terraform
state, database passwords, shell history, and Claude AI / Kiro IDE settings), gzipped
the result and exfiltrated it to infrastructure masquerading as Azure
(`azurestaticprovider[.]net`). The fabricated 9.x line — which had never shipped a CJS
bundle — guaranteed that anyone on `^9`, `~9.1`, `^12` or `~12.0` ranges received the
payload on their next install or lockfile refresh. Vendors flagged the versions within
hours of publication.

## How it went wrong

The compromise was of an identity, not a pipeline: publish rights on a dormant,
widely-depended-on package were recovered through an expired email domain, and three
tarballs were published in one operation (the CJS payload is byte-identical across all
three). On the victim side the sequence is deliberately boring: an `npm install`
resolving a caret range unpacks the tarball into `node_modules`, and at install time
nothing anomalous happens at all — no lifecycle script, no child process, no write
outside `node_modules`. Hours or days later, the developer's application or build tool
requires `node-ipc`, and the IIFE runs inside the already-running, fully legitimate
`node` process: it enumerates the filesystem, reads the credential stores, writes a
gzip archive under `$TMPDIR/nt-*`, marks itself with an `__ntw=1` environment flag, and
makes outbound connections (including UDP/53) to the C2. From the operating system's
point of view the entire payload is file reads plus one network flow from a trusted
binary — no new exec, no temp-dir executable, no install-time signature.

## What the firewall should learn

The only point where the payload's identity is argv-visible is the install gate, and
this incident is the exact shape the reactive malicious-version feed (SC 7) catches —
but the two signals that fire *earlier* than a malware verdict are proactive feed
material checked against the same install argv: release freshness and revival from
dormancy (SC 23), which would have held `node-ipc@12.0.1` on the day it was published.
The runtime trigger proves the post-install limit honestly: once the package is
required, the stealer runs as reads and a single flow from a legitimate process, and no
exec/input rule can see an `import` — the win is at the gate, not at runtime. Two
secondary observables stay report-grade: the temp-archive-then-connect shape is the
collector-upload pattern the network pack already covers, and the harvest list — which
explicitly includes Claude and Kiro AI-tool settings — confirms that the agent's own
config directories belong in the credential-file inventory alongside `.aws` and `.ssh`
(`filesystem.credentials.read`).

## Sources

- [StepSecurity: Active Supply Chain Attack — Malicious node-ipc Versions Published to npm](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- [Snyk: Malicious node-ipc Versions Published to npm (SNYK-JS-NODEIPC-16697063)](https://snyk.io/blog/malicious-node-ipc-versions-published-npm/)
