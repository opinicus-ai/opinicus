# chalk and debug npm packages compromised: a crypto-clipper shipped to billions of weekly downloads

- Date: 2025-09-08 | Agent/tool: chalk@5.6.1, debug@4.4.2 and 16 other compromised npm packages | Axis: supply

## What happened

Starting September 8, 2025 at 13:16 UTC, eighteen high-traffic npm packages were published with malicious code after their common maintainer, Josh Junon (Qix-), fell for a phishing email from `support@npmjs.help` — a look-alike domain registered three days earlier. The poisoned releases included `chalk@5.6.1` (300M weekly downloads), `debug@4.4.2` (357M), `ansi-styles`, `strip-ansi`, `color-convert`, `supports-color`, `wrap-ansi` and others, together north of two billion downloads per week. Each package gained a few lines of obfuscated JavaScript in its `index.js`. The payload was not a Node infostealer but a browser-context crypto clipper: once any code from these packages is bundled into a website, it hooks `fetch` and `XMLHttpRequest`, rewrites wallet addresses inside HTTP responses (swapping the real destination for an attacker address chosen by Levenshtein-distance look-alike), and monkey-patches `window.ethereum.request` so that `eth_sendTransaction`, Solana sign requests and ERC-20 approval calls are silently redirected to attacker-controlled addresses. Aikido detected the wave within minutes; most packages were unpublished within an hour. The same attackers phished a second maintainer the same day, hitting the duckdb packages around 16:58 UTC.

## How it went wrong

The compromise needed no exploit on the victim machine: a phishing email harvested a maintainer's npm token, and the token published trojanized versions that carry the clipper inside an ordinary dependency. Any build that pulled the versions — often via `npm install` resolving a caret range or an agent happily running `npm update` — vendored the code into browser bundles. From the OS point of view the whole incident is silent: no strange process, no unusual file access, no suspicious exec. The malicious behavior happens inside the user's browser at transaction-signing time, in JavaScript that came from `node_modules` weeks earlier. Discovery came from a human noticing that npm-hosted versions had no matching commits in the repository (reported on the debug-js/debug tracker, issue #1005), not from any runtime signal.

## What the firewall should learn

This is the supply-chain case that proves install-time gating is the only reliable choke point, because post-install there is nothing to see. What a ptrace monitor can still do: (1) a maintained deny feed of malicious `name@version` pairs checked against the argv of every `npm|pnpm|yarn|bun install`/`npx|bunx` exec in the session — `chalk@5.6.1` and `debug@4.4.2` were identifiable by name and version within the hour, far faster than machines stop building; (2) gate ad-hoc installs that are not part of the project's manifest or lockfile, since a dependency refresh is the moment the clipper walks in; (3) session-level observation — record every package name@version installed during a session so incident response can answer "am I affected?" in seconds instead of grepping lockfiles; (4) honesty about the limit: the clipper's actual misbehavior (response rewriting, transaction hijacking) is invisible at the OS layer on the developer machine, so the catalog must not claim coverage it cannot deliver — the win is at the install gate, not at runtime.

## Sources

- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Semgrep: chalk, debug and color on npm compromised in new supply chain attack](https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack)
- [Checkmarx: Chalk and 17 other npm packages compromised](https://checkmarx.com/zero-post/chalk-and-17-other-npm-packages-compromised-in-supply-chain-attack/)
- [debug-js/debug issue #1005 — discovery thread](https://github.com/debug-js/debug/issues/1005)
