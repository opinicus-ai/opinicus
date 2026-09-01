# The bypass harness

The adversarial measurement of `[af-1]`: what do the two shipping sensors —
exec `ptrace` and the `seccomp` filter — hold, see, and miss, when the
attacks arrive on purpose? The numbers live in [FINDINGS.md](FINDINGS.md).

## Layout

| path | what it is |
| --- | --- |
| `techniques/` | one small program per technique, C unless named `.go` or `pydrop`; `build.sh` compiles them into `bin/` |
| `policies/catchall.yaml` | the capability probe: holds every action kind the sensors can deliver. Harness equipment, not product policy |
| `orchestrate.py` | runs every cell: baseline (no firewall), builtin (product posture), probe (capability), across the three filter modes; `--preload` adds the `[af-2]` pass that re-runs the product posture with the in-process sensor active |
| `classify.py` | verifies effects from the filesystem and the listener log, parses traces structurally, prints the matrix; the sensor columns show which silent cells the in-process sensor moved to seen |
| `benign.sh` + `corpus.sh` | the scripted normal dev session that must run with zero questions; `corpus.sh` is shared with the in-process sensor spike |
| `floor-stress.sh` | the `[af-12]` Landlock floor stress matrix: symlink, hard link, bind mount, git worktree, `/tmp`-shape and io_uring cases against the real product, each row pinned to `docs/LANDLOCK-CONTRACT.md` |
| `benign-gate.sh` | the fast benign gate of `[af-10]`: one representative corpus mode (write-only) end to end plus a FAIL-scan of the whole `results/benign-summary.txt`; wired into `scripts/gate.sh` after quiet-check |
| `tamper.sh` | the `[af-4]` gate: the four seeded tamper techniques must fire every time, the quarantine rules must hold the tree, and the report rules must not ask; the negative side is `benign.sh` |
| `evidence.sh` | the `[af-9]` gate: the seeded audit-trail erasures (trace truncation and forgery, sensor-record truncation, rohrpost history erasure, transcript tampering, the unlink gaps) must land on their measured outcome — prevented, sensed or an explicit gap; the negative side is `benign.sh` and the in-file negative tests of `policies/tamper.yaml` |
| `inherit.sh` | the inherited-descriptor gate of `[af-12]`: the launcher vector must be closed by the launch hygiene (`close_beyond_stdio`), and the in-tree fork-inheritance and `SCM_RIGHTS` rows are measured and named; the fixtures are `techniques/inherit-fd.c` and `techniques/inherit-scm.c` |
| `hostile.sh` | the `[af-12]` gate: five techniques (`hostile-ptrace`, `hostile-vmem`, `hostile-procmem`, `hostile-pidfd`, `hostile-extkill`) attack the monitor from **outside** the tree under every yama `ptrace_scope` 0–3; every cell reads `denied-by-kernel`, `succeeded-unsensed` or `succeeded-fail-closed`, and needs passwordless `sudo` for the sysctl (restored by trap) |
| `correlate.sh` | the `[af-5]` gate: `agent-firewall correlate` compares the sensor's record with the monitor's trace on the seeded discrepancy techniques and on the benign corpus, and the three rules of `policies/correlation.yaml` ship only on the benign side firing zero |
| `uring-compat.sh` | the `[af-12]` compatibility matrix (EXP-T1): the benign corpus in all three modes plus real workloads, each once with no firewall and once under the deny of `tamper.bypass.io-uring`; the numbers behind the default-deny decision (`docs/DECISIONS.md`, 2026-09-01) |
| `run.sh` | everything, then the classification, then the corpus |
| `results/` | raw runs (regenerable, not committed) |

`results/benign-summary.txt` is the append-only ledger of every benign
run: one line per `benign.sh` invocation, from this harness, the
in-process sensor spike (`run-corpus.sh`), `correlate.sh`, and the gate.
Every line must read `questions=0 agent_tags=0 quarantines=0 fw_exit=0`;
a `FAIL` line is a measured regression of the interruption budget. The
ledger is gitignored, so `benign-gate.sh` refuses any `FAIL` anywhere in
it — a regression cannot hide behind a green gate. Regenerate the ledger
the honest way: truncate it and run the corpus again in all three modes
(plain, sensor-active as `run-corpus.sh` sets it, and sensor-active with
the copied library as `correlate.sh` sets it); never edit a line in place.

## Usage

```sh
./run.sh                # the full matrix plus the benign corpus
python3 orchestrate.py  # the runs only
python3 classify.py     # re-print the matrix from results/
./benign.sh all-opens   # the corpus at one filter mode
./benign-gate.sh        # the fast gate step: one mode end to end, plus a FAIL-scan of the summary
./tamper.sh             # the tamper gate of [af-4]
./hostile.sh            # the hostile same-UID gate of [af-12] (sudo for yama)
./correlate.sh          # the correlation gate of [af-5]
./inherit.sh            # the inherited-descriptor gate of [af-12]
```

Requires the release build (`cargo build --release`), `cc`, `go`, and the
port 45777 free. Runs as a normal user; nothing needs root and nothing
touches a real credential store — the credential technique reads a file the
harness planted in its own scratch tree, and the kill-monitor technique
kills only the process that traces itself.

Every technique is independent: it performs its action, reports one
`ACTION` line, and the classifier verifies the effect from outside. Add a
technique by writing the program, adding it to `orchestrate.py` and to
`ACTIONS`/`SCENARIOS` in `classify.py`, and citing the catalogue scenario it
probes.
