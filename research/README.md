# Research

Everything measured or researched, and the home of the work the direction of
record asks for. [docs/DIRECTION.md](../docs/DIRECTION.md) §11 holds the
learning plan and the workstream table; this page is the index of where
research lives and where new work goes.

## What exists

| area | path | what it holds |
| --- | --- | --- |
| Benchmark | `bench/bench.sh` | the shared W1/W2/W3 workload; every spike and every future mechanism is measured against it. `bench/quiet-check.sh` keeps the demo quiet. |
| Baseline spikes | `spikes/baselines/` | cost and coverage of the cheap mechanisms; the `/proc` polling and `LD_PRELOAD` measurements |
| seccomp + ptrace spike | `spikes/seccomp-ptrace/` | the `RET_TRACE` filter and its cost curve — now shipped in `af-monitor` |
| seccomp user-notify spike | `spikes/seccomp-unotify/` | argument reliability, the 47.6% path race |
| Landlock spike | `spikes/landlock/` | in-kernel "always no" rules, the privileged tier survey |
| Bypass harness | `bypass/` | the adversarial matrix of `[af-1]`: what the shipping sensors hold, see, and miss. Read [bypass/FINDINGS.md](bypass/FINDINGS.md) |
| Threat catalogue | `threats/` | 10 axes, incident reports, scenarios, the ledger, the reusable research workflow. Has its own [README](threats/README.md). |

Every spike keeps its own `FINDINGS.md` with raw numbers and runnable code.
Numbers without a runnable re-measurement do not belong in the documents.

## What goes where next

| workstream | home | first output |
| --- | --- | --- |
| W1 — in-process sensor spike (`LD_PRELOAD` shim emitting `af-core` events) | `spikes/inprocess/` | `FINDINGS.md`: what semantics the sensor adds, what its presence and absence look like from outside |
| W3 — agent detection prototype | `detection/` | signal inventory and confidence measurements for the detector subsystem |
| W8 — Windows hooking survey | `spikes/windows-notes/` | a survey document; no code until the Linux learning loop runs |

The threat-research workflow (`threats/README.md`) keeps running unchanged.
It is the manual front end of the pipeline that
[docs/DIRECTION.md](../docs/DIRECTION.md) §8 industrializes; its governance
rule — research agents never publish production rules — is binding.
