# VM lab findings

## 2026-09-01 — the full four-scope yama matrix, unprivileged, host untouched

`yama-sweep.sh` round 1 (evidence/2026-09-01-unprivileged-round1.txt),
Fedora Cloud 43, kernel 6.17.1-300.fc43, KVM, measurement as the
unprivileged user `bench` (only the sysctl changes ride sudo — yama
exempts CAP_SYS_PTRACE holders at scopes 0–2, so a root-run sweep
measures nothing; that was round "root" and is kept as the negative
proof of why the unprivileged run is the only honest one):

| scope | attach/vmem/procmem | pidfd_getfd | signals (pidfd, external) | session |
|---|---|---|---|---|
| 0 | succeed, unsensed | ok | kill the monitor — fail-closed every time (EXITKILL, durable trace, exit 137) | runs |
| 1 | denied by kernel (EPERM/EACCES) | EPERM | still kill the monitor — fail-closed | runs |
| 2 | no session: TRACEME refused, monitor never started (exit 2) | — | — | refused |
| 3 | no session (identical) | — | — | refused |

Scope 3 is one-way per boot: the VM took the road, ended latched at 3
("original: 0"), and was destroyed — **the host's scope was 3 before and
after every round, asserted by the sweep itself.** The two root-cause
lessons of 2026-09-01, reproduced and confined: the kernel's one-way
rule, and the value of measuring where the dial is disposable.

Matches the reference-host evidence of [af-12] at scopes 0–1; scopes 2–3
now carry a second, independent measurement.

Exit gate status (AF-fnejbc): round 1 of 3 green; cold boot 26–34 s.
