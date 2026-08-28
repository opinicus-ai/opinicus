# Mastra npm packages backdoored via the easy-day-js typosquat
- Date: 2026-06-17 | Agent/tool: npm; Mastra AI framework packages (`@mastra/*`, `mastra`) | Axis: supply

## What happened
On June 17, 2026 an attacker published `easy-day-js@1.11.21` — a clean,
functional copy of the `dayjs` date library with wholesale-copied metadata
(author `iamkun`, homepage, repository URL, mirrored `1.11.x` versioning) —
and, after compromising the `@mastra` organization's publishing credentials,
injected it as a production dependency across 140+ Mastra ecosystem packages
in an 88-minute automated publish campaign. The dependency was pinned as
`^1.11.21`, so npm resolved to the latest matching version at install time.
Hours later the attacker published `easy-day-js@1.11.22`, identical except
for a 4,572-byte obfuscated `setup.cjs` and a `postinstall` hook that runs
it. Every fresh `npm install` of an affected package then executed the
dropper: it disabled TLS certificate verification, downloaded a second stage
from `23.254.164.92:8000`, wrote it to a random-named `.js` file in the temp
directory, spawned it as a detached background process with a C2 argument of
`23.254.164.123:443`, and deleted itself. Packages with more than 1.1
million combined weekly downloads were exposed. Microsoft attributes the
campaign to Sapphire Sleet, which ran a separate Axios npm compromise in
April 2026.

## How it went wrong
The victim-side process tree is short and fully machine-visible. `npm
install @mastra/core` resolves `easy-day-js` to `1.11.22` and runs the
package's `postinstall`: `node setup.cjs --no-warnings`, a child of the npm
process. The script sets `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`,
fetches the stage-2 payload over HTTPS, writes it to
`os.tmpdir()/<12-random-bytes-hex>.js`, and calls `child_process.spawn(process.execPath,
[filepath, stage2C2], { detached: true, stdio: 'ignore' }).unref()` — so the
payload keeps running after npm exits, with no output. A `finally` block
runs `fs.rmSync(__filename)`, deleting `setup.cjs` from the package tree.
The clean-bait-then-range trick means nothing on the victim side differs at
commit time: no manifest diff, no rename, just a range that resolves
differently the day the attacker publishes.

## What the firewall should learn
Three observables fire before any damage. (1) The postinstall child `node
setup.cjs` under an `npm install` ancestry — the install-ancestry gate this
catalog already proposes (SC 1), and the real rules' `process.install.hook-child`
reports but does not gate. (2) `node /tmp/<random>.js` — an interpreter
whose script *argument* is a temp path. `process.exec.from-temp` matches exe
paths only, so this shape is invisible today; the argv half is the missing
rule. (3) `NODE_TLS_REJECT_UNAUTHORIZED=0` appears in the environment of
every process the dropper spawns, and env is an exec observable. The
detached spawn survives npm's exit, but the exec event happens while the
install ancestry is still intact, so ancestry rules see it at spawn time.

## Sources
- [StepSecurity: Mastra npm Supply Chain Attack — 140+ Packages Backdoored via easy-day-js Typosquat](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)
- [Microsoft Threat Intelligence: From package to postinstall payload — inside the Mastra npm supply chain compromise by Sapphire Sleet](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
