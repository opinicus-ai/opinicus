# Symbiote loaded itself via LD_PRELOAD into every process — including the monitoring tools

- Date: 2022-06 | Agent/tool: Symbiote Linux userland rootkit (shared object; financial sector, Latin America) | Axis: evade

## What happened

On June 9, 2022, Intezer and BlackBerry jointly published the analysis of Symbiote, a Linux malware they called "nearly impossible to detect". Earliest samples date to November 2021 and the tooling impersonated major Brazilian banks, suggesting financial-sector targets in Latin America. Symbiote is not a standalone program: it is a shared object that the dynamic linker loads via `LD_PRELOAD` into every running process on the machine. Once inside, it hides its own files, processes and network traffic from every tool the operator might use, harvests SSH credentials, and provides the attacker a backdoor with root access. Live forensics on an infected machine turned up nothing, because the tools doing the forensics had the rootkit loaded inside them.

## How it went wrong

Because `LD_PRELOAD` objects load before everything else, Symbiote's hooks on libc and libpcap win over both the application and any monitoring software. It scrubbed process listings by filtering `/proc` output, handed tools a cleaned fake `/proc/net/tcp` through a hooked `fopen`, and prepended its own eBPF packet-filter bytecode so packet captures silently dropped its own traffic. It even hooked `execve` to detect when a user ran `ldd` (via the `LD_TRACE_LOADED_OBJECTS=1` environment variable) and removed itself from the output. Credential theft came from hooking `read` inside `ssh` and `scp` processes, with stolen passwords exfiltrated as hex-encoded chunks in DNS A-record queries. A backdoor through hooked PAM functions let the attacker log in as any user, and a `setuid` copy combined with the environment variable trick `HTTP_SETTHIS="/bin/bash -p" /bin/true` spawned a root shell. Instead of killing the monitors, Symbiote became part of them.

## What the firewall should learn

The environment of an exec is a code-loading vector, and it is directly observable: `exec(env)` should gate any `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` or `GLIBC_TUNABLES` value that points outside trusted system directories, and `file_open(/etc/ld.so.preload, write)` deserves deny. Environment variables that hold command strings (the `HTTP_SETTHIS` pattern) are a second shape worth matching on values of sensitive execs. The deeper lesson is monitor hygiene, stated by Intezer itself: security tooling must be statically linked, because a userland rootkit infects the very processes that watch the system. The firewall's monitor and its decision path must not inherit or load anything from the environment of the processes it traces, and it should flag descendant execs whose environment tries to hand it one.

## Sources

- [Intezer: Symbiote Deep-Dive - Analysis of a New, Nearly-Impossible-to-Detect Linux Threat](https://intezer.com/blog/new-linux-threat-symbiote)
- [BlackBerry: Symbiote - A New, Nearly-Impossible-to-Detect Linux Threat](https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat)
