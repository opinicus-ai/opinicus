# PyPI package 'secretslib' dropped a fileless Monero miner with memfd_create

- Date: 2022-08 | Agent/tool: PyPI package 'secretslib' (setup.py install script) | Axis: evade

## What happened

Sonatype reported a malicious PyPI package named `secretslib` in August 2022. The package claimed to do "secrets matching and verification made easy". It contained no such code. Installing it ran shell commands hidden in base64 inside `setup.py`. The commands downloaded a stripped ELF binary, ran it with sudo, and deleted it at once. The binary then loaded a second program directly into memory with the `memfd_create` syscall. That second program was a Monero cryptominer. The package author field impersonated a real engineer at Argonne National Laboratory. The package reached fewer than 100 downloads before it was removed from PyPI.

## How it went wrong

The chain was built to be invisible. `setup.py` held one base64 string that decoded to: install `wget` and `cpulimit`, fetch `tox` from a raw IP, `chmod +x`, run `sudo ./tox`, then `rm ./tox`. The stripped `tox` binary had a zero detection rate on VirusTotal at the time, because stripping removes the strings and debug info scanners rely on. Once running, `tox` used `memfd_create` to create an anonymous in-memory file, wrote the real payload (a Monero miner, seen on VirusTotal as `memfd (deleted)`) into it, and executed it from memory. Nothing executable ever rested on disk. `cpulimit` kept CPU use low so the miner would not stand out. Deleting `tox` after launch left forensic analysts with almost nothing. The fake author identity borrowed trust from a real national laboratory engineer.

## What the firewall should learn

Every stage here is a classic evasion move against file-based tools, but the OS stream still shows all of it. The `input` observable (the decoded base64 script text) and the exec chain (`wget` -> `chmod +x` -> `sudo` -> short-lived ELF) are visible. Rule ideas: approval_required for any exec whose `exe` path is `/memfd:*` or `/proc/self/fd/N`, because that is a fileless program; approval_required for an exec of a file that was written and deleted within the same session (write-then-exec correlation); the existing temp-directory and decode-to-shell rules already raise the first flag. An exec whose parent exited immediately after spawning it (loader pattern) should also be reported.

## Sources

- [Sonatype: PyPI Package 'secretslib' Drops Fileless Linux Malware to Mine Monero](https://www.sonatype.com/blog/pypi-package-secretslib-drops-fileless-linux-malware-to-mine-monero)
- [The Hacker News: Newly Uncovered PyPI Package Drops Fileless Cryptominer to Linux Systems](https://thehackernews.com/2022/08/newly-uncovered-pypi-package-drops.html)
