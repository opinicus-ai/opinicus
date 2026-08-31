# Quasar Linux (QLNX) compiled its rootkit on the developer's machine with the host's own gcc

- Date: 2026-05-04 | Agent/tool: Quasar Linux RAT (QLNX) against developer and DevOps endpoints | Axis: evade

## What happened

Trend Micro Research documented Quasar Linux (QLNX), a previously undocumented
full-featured Linux remote access trojan with an unusually small detection
footprint, built for exactly the endpoint this firewall watches: the developer
workstation. Its credential harvester sweeps `.npmrc`, `.pypirc`,
`.git-credentials`, `.aws/credentials`, `.kube/config`, `.docker/config.json`,
Vault and Terraform tokens, GitHub CLI tokens and `.env` files — the keys to
package registries, cloud accounts and CI/CD pipelines. To hide, the implant
re-executes itself from a `memfd` and deletes its on-disk binary, spoofs its
process name as a kernel worker thread, and timestomps its artifacts against
`libc`. Its rootkit and PAM backdoor are not shipped as binaries: QLNX carries
their C source as embedded string literals and compiles them on the target
with the host's own `gcc`, then installs them via `/etc/ld.so.preload`, where
they load into every dynamically linked process on the machine. Trend's
framing is explicit: a single compromised maintainer workstation feeds the
supply-chain kill chain — the same shape as the LiteLLM compromise of March
2026.

## How it went wrong

On start QLNX probes `/proc/sys/kernel/yama/ptrace_scope` (gating its later
ptrace/`/proc/pid/mem` injection), probes for `gcc`, and checks whether it is
already running from memory by reading `/proc/self/exe` for `memfd:` or
`(deleted)`. If not, it `memfd_create`s an anonymous file, copies itself into
it in 8 KB chunks, `unlink`s the original binary, and re-executes via
`execveat` (falling back to `/proc/self/fd/N`) — the process tree then shows a
running program whose exe is `/memfd:... (deleted)` and nothing on disk.
It masks as `[kworker/0:0]`-style kernel threads by overwriting `argv[0]`,
calling `prctl(PR_SET_NAME)` and writing `/proc/self/comm`, and scrubs the
`_` and `OLDPWD` shell variables from its environment to blur its origin.
The compile-on-target stage writes hidden source files (`/tmp/.hide_src_*`),
forks `gcc -shared -fPIC -o /usr/lib/libsecurity_utils.so.1`, deletes the
source, appends the `.so` to `/etc/ld.so.preload`, and copies `libc`'s
timestamps onto the artifact with `utimensat`. From then on every
dynamically linked process — `ls`, `ps`, `ssh`, any monitor tool — loads the
rootkit, which hooks `readdir`, `stat`, `open`, `fopen` and `access` via
`dlsym(RTLD_NEXT)` to return `ENOENT` for the implant's files and PID; killing
the process without first cleaning `ld.so.preload` just respawns it on the
next exec. A second tier uses eBPF hash maps (root, kernel ≥ 4.18) to hide up
to 64 PIDs, 64 file paths and 32 ports from kernel-visible tools.

## What the firewall should learn

The chain is visible in shipped observables before any hiding starts:
file_open(write) of a hidden dot-source under `/tmp` → exec(`gcc`, `-shared
-fPIC -o /usr/lib/*.so`) → file_open(`/etc/ld.so.preload`, write, already
deny) is a three-step write-compile-install chain that session correlation
(SC evade-05) can escalate, and `process.exec.fileless` already names the
`/memfd:`/`(deleted)` exe path the re-exec produces. New rule idea from the
spoofing step: an exec whose comm/argv[0] is a bracketed kernel-thread name
(`kworker*`, `ksoftirqd*`, `rcu_*`, `migration*`, `watchdog*`) while the exe
path is a user-space file is always a lie — terminate. Honest gaps: the
`yama/ptrace_scope` read and the credential read-sweep are read-side events
invisible in the default write-only filter (the research sensor's file_read
sees them when active), and timestomping rides `utimensat`, outside the four
observables — the usable proxy is file_open(write) under `/usr/lib` or
`/etc` from agent ancestry, which the tree never has a reason to do.

## Sources

- [Trend Micro Research: Quasar Linux (QLNX) – A Silent Foothold in the Supply Chain: Inside a Full-Featured Linux RAT With Rootkit, PAM Backdoor, Credential Harvesting Capabilities](https://www.trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html)
