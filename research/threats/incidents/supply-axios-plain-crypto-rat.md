# axios compromise smuggled a RAT in as an added dependency, pre-staged with a decoy release

- Date: 2026-03-31 | Agent/tool: npm; `axios`@1.14.1/0.30.4, `plain-crypto-js`@4.2.1 | Axis: supply
## What happened

On March 31, 2026, between ~00:21 and ~03:30 UTC, malicious versions of `axios` — one
of the most-depended-on HTTP clients in the npm ecosystem — were published from a
compromised maintainer account: 1.14.1 on the current line and 0.30.4 on the legacy
0.x line. The axios code itself was not the payload: each malicious release silently
added a new dependency, `plain-crypto-js`@4.2.1, whose `postinstall` script is a
cross-platform remote access trojan that contacts a command-and-control server and
fetches platform-specific second stages for macOS, Windows and Linux. The actor
pre-staged legitimacy the day before: a throwaway account published a benign
`plain-crypto-js`@4.2.0 first, so the dependency the poisoned axios releases pulled in
arrived with release history. Poisoning both major lines at once maximized the semver
blast radius, exactly as later waves did. npm removed the versions after roughly three
hours, but any install — especially in CI — that resolved them in that window executed
the RAT. Arctic Wolf's concrete follow-up recommendation for consumers was a release-age
quarantine: `npm config set min-release-age 3`.

## How it went wrong

Stolen or recovered maintainer credentials produced an `npm publish` whose only
malicious content was one line added to `package.json` (the dependency) plus the
attacker's package. On the victim machine nothing is edited: `npm install` resolves the
new dependency edge that was weaponized at publish time, downloads
`plain-crypto-js`@4.2.1, and runs its postinstall as a child of the package manager —
process tree `npm install` → `sh -c node <postinstall>` → outbound connect to C2 →
download payload → write to disk → execute. There is no curl-pipe, no manifest edit, no
git command for a victim-side rule to notice; lockfile-reviewed projects only see the
new dependency when the lockfile refresh is diffed, and agents that run bare installs
see nothing at all. The decoy-history trick means even "is this package old and
established?" heuristics were answered the way the attacker wanted.

## What the firewall should learn

The postinstall → C2-connect → drop → exec chain is precisely the install-ancestry gate
(SC 1) plus drop-then-execute (SC 11), and the shipped `process.install.hook-child` rule
covers the download-tool child — this incident confirms those gates, it does not break
them. What it adds: the payload entered through a *dependency edge added at publish
time*, so the highest-value victim-side artifact is the session's install record of
every name@version (SC 5/SC 9 bookkeeping), which turns "are we affected?" into a
lookup instead of a grep across CI logs; and the decoy package age means a freshness
gate (SC 23) must bind to the *resolved version's* publish timestamp, not to the
package's age. The dual-major publish repeats the node-ipc pattern, so a
name@version feed must not assume one malicious version per line.

## Sources

- [Arctic Wolf: Supply Chain Attack Impacts Widely Used Axios npm Package](https://arcticwolf.com/resources/blog/supply-chain-attack-impacts-widely-used-axios-npm-package/)
- [Socket: axios npm package compromised](https://socket.dev/blog/axios-npm-package-compromised)
