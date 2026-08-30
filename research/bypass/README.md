# The bypass harness

The adversarial measurement of `[af-1]`: what do the two shipping sensors —
exec `ptrace` and the `seccomp` filter — hold, see, and miss, when the
attacks arrive on purpose? The numbers live in [FINDINGS.md](FINDINGS.md).

## Layout

| path | what it is |
| --- | --- |
| `techniques/` | one small program per technique, C unless named `.go` or `pydrop`; `build.sh` compiles them into `bin/` |
| `policies/catchall.yaml` | the capability probe: holds every action kind the sensors can deliver. Harness equipment, not product policy |
| `orchestrate.py` | runs every cell: baseline (no firewall), builtin (product posture), probe (capability), across the three filter modes |
| `classify.py` | verifies effects from the filesystem and the listener log, parses traces structurally, prints the matrix |
| `benign.sh` | the scripted normal dev session that must run with zero questions |
| `run.sh` | everything, then the classification, then the corpus |
| `results/` | raw runs (regenerable, not committed) |

## Usage

```sh
./run.sh                # the full matrix plus the benign corpus
python3 orchestrate.py  # the runs only
python3 classify.py     # re-print the matrix from results/
./benign.sh all-opens   # the corpus at one filter mode
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
