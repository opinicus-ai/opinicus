# Backdoored @solana/web3.js npm release exfiltrated private keys through the app's own process

- Date: 2024-12-03 | Agent/tool: @solana/web3.js npm package (450k+ weekly downloads) | Axis: supply

## What happened

On December 3, 2024, a publish-access account for the @solana/web3.js npm package was compromised, apparently through phishing. Within a roughly five-hour window the attacker published two unauthorized versions, 1.95.6 and 1.95.7. The versions carried a backdoor: a new function named `addToQueue` that collected private key material used for transaction signing and sent it to an attacker endpoint, dressed up with headers that mimicked Cloudflare traffic. Apps that handle raw keys, such as trading bots, leaked those keys simply by running the updated library. The project's GitHub advisory (GHSA-jcxm-7wvp-g6p5, High) warned that any machine with the package installed or running should be considered fully compromised. The versions were caught within hours, unpublished, and replaced by 1.95.8.

## How it went wrong

There was no exploit, no shell, and no extra process. `npm install` pulled the trojanized tarball, and the backdoor ran inside the victim application's own node process when it did key-handling work. The malicious code read in-memory key material and issued an ordinary HTTPS POST to the attacker's host. From the outside this looks like the app phoning a new API host. The user's agent or terminal only ever ran `npm install` and then the app; every subsequent action happened inside a trusted process.

## What the firewall should learn

This is the hard case for supply-chain defense: the malicious code runs inside a legitimate interpreter with no suspicious exec at all. What remains observable is the network_connect to a host this process tree never talked to before, and the install event that preceded it. Rule ideas: (1) keep a per-session baseline of egress hosts; a network_connect from a node (or python) process to an external host not seen before a recent package install is approval_required; (2) correlate ancestry: a process whose tree contains a fresh npm/pnpm install followed by first-time egress to a non-registry host is the solana shape (decision: approval_required); (3) at minimum, observe and report every first connection to an unknown external host from freshly-installed dependencies, because silent observation is the only honest fallback when no exec signature exists.

## Sources

- [GitHub advisory GHSA-jcxm-7wvp-g6p5: Modified package published to npm, containing malware that exfiltrates private key material](https://github.com/solana-labs/solana-web3.js/security/advisories/GHSA-jcxm-7wvp-g6p5)
- [Socket: Supply Chain Attack Detected in Solana's web3.js Library](https://socket.dev/blog/supply-chain-attack-solana-web3-js-library)
- [ReversingLabs: Malware found in Solana npm library raises the bar for crypto security](https://www.reversinglabs.com/blog/malware-found-in-solana-npm-library-with-50m-downloads)
