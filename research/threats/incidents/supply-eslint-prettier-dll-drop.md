# eslint-config-prettier compromise: a phished token shipped a DLL-dropping install script to 30M weekly installs

- Date: 2025-07-18 | Agent/tool: eslint-config-prettier and sibling npm packages, npm postinstall hook, rundll32 | Axis: supply

## What happened

On July 18, 2025, four versions of `eslint-config-prettier` (8.10.1, 9.1.1, 10.1.6, 10.1.7) — a linting config with about 30 million weekly downloads — appeared on npm with no corresponding commits in the GitHub repository. Maintainer JounQin had been phished through a spoofed npm support page on the typosquatted domain `npnjs[.]com`; a new npm token was created in his account and used to publish the malicious releases. The payload was an install script (`install.js`) whose innocuously named `logDiskSpace()` function did not log anything: on Windows it executed a DLL (`node-gyp.dll`) bundled inside the npm tarball via `rundll32`, giving the attacker remote code execution with the privileges of the user or CI runner. On Linux and macOS the script exited immediately, which kept the blast radius mostly off Linux CI. The campaign widened the same way within days: versions of `eslint-plugin-prettier`, `synckit`, `@pkgr/core`, `napi-postinstall`, the `is` package (3.3.1, 5.0.0) and `got-fetch` (5.1.11, 5.1.12) were published with malware by phished maintainers. A community member flagged the version mismatch about an hour after publish (issue #339), the token was revoked, and the malicious versions were deprecated; the incident is tracked as CVE-2025-54313.

## How it went wrong

The mechanism is the minimal npm attack: phish one maintainer → publish trojanized versions → let the ecosystem's own automation pull them in. The execution half was a textbook lifecycle-hook delivery: `npm install eslint-config-prettier@10.1.7` → npm runs the package's `install.js` → the script detects Windows, unpacks the bundled DLL from the tarball and launches `rundll32` on it → attacker code runs inside a normal, unsuspicious process spawned by a routine dependency install. Nothing about the process tree looked wrong to the user or to most CI logging: it is the same shape a legitimate native module's `node-gyp` build takes. Discovery depended on an off-band signal — published versions with no repository commits — which is a registry-side property no end-point saw.

## What the firewall should learn

This incident is the cleanest argument for gating what a package install is allowed to spawn. Observable signals and rule ideas: (1) ancestry — `npm|pnpm|yarn|bun install` at the root, `node .../install.js` beneath it, then an exec of a system binary launcher (`rundll32` on Windows; on Linux the analog is a hook execing `sh`, `curl`, `ld.so` or an unpacked binary) is `approval_required`, because lint-config packages have no business launching native loaders; (2) file_open writes of binary artifacts (`.dll`, `.so`, `.node`) extracted under `node_modules/` during install, followed within seconds by an exec touching the same path — the drop-and-execute pair — escalated from a report to `approval_required` when the ancestry root is an install command; (3) session-level name@version recording of everything installed (the deny-feed scenario) so waves like this one — four exact versions, deprecated within hours — can be blocked by a feed update mid-incident; (4) honesty note: "versions with no matching commits" is registry metadata, not observable at the ptrace layer, so that detection belongs to lockfile/provenance tooling, not to the firewall.

## Sources

- [Endor Labs: CVE-2025-54313 eslint-config-prettier Compromise — High Severity but Windows-Only](https://www.endorlabs.com/learn/cve-2025-54313-eslint-config-prettier-compromise----high-severity-but-windows-only)
- [StepSecurity: eslint-config-prettier Package Shows Signs of Compromise](https://www.stepsecurity.io/blog/supply-chain-security-alert-eslint-config-prettier-package-shows-signs-of-compromise)
- [prettier/eslint-config-prettier issue #339 — discovery thread](https://github.com/prettier/eslint-config-prettier/issues/339)
- [Snyk: Maintainers of ESLint Prettier plugin attacked via npm supply chain malware](https://snyk.io/blog/maintainers-of-eslint-prettier-plugin-attacked-via-npm-supply-chain-malware/)
