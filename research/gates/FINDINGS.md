# The gate evidence of [af-10]

**Run:** GitHub Actions run 33475574579 (`gate-20x`, workflow_dispatch on
`main` at `e35e507`, 2026-09-01). Twenty consecutive executions of
`scripts/gate.sh` — the complete gate — on one clean GitHub-hosted
`ubuntu-24.04` runner (yama `ptrace_scope=1`, kernel 6.x, `/bin/sh` = dash,
4 vCPU), back to back, first run cold.

**Result: 20 of 20 green.** Every run executed the identical check
sequence (compared programmatically over the twenty logs):

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. supply chain (cargo-deny advisories/bans/licenses/sources, cargo-audit)
4. `cargo test --workspace`
5. `cargo build --release`
6. build the in-process sensor
7. `policy check`
8. `policy test` — 705 in-file policy tests every run
9. e2e — 54/54 assertions every run (now with the §U io_uring and K9–K12
   Landlock-contract sections), exit 0
10. quiet-check — quiet on everyday work, every dangerous command stopped
11. benign gate — one corpus mode end to end, no FAIL line in the summary
12. count-rules — exit 0, the pack (161 rules) and the floor classification
    in step
13. threat-ledger check — ledger agrees with disk

The raw log of every run sits next to this file (`run-1.log` …
`run-20.log`).

**The synthetic red:** PR #3 (`red-synthetic-check`, commit `2b8565f`)
inverted B2 — the e2e assertion that a denied session's marker file holds
no `DROP DATABASE` line. The required check `gate` failed on it (run
33473850536's successor 33475663925, job 99754278689) and branch protection
reported the pull `blocked`; it was closed unmerged.

## The open follow-up: the rare IO-safety abort

A second, rarer flake surfaced during this work and is **not** covered by
the 20-run evidence above: `fatal runtime error: IO Safety violation:
owned file descriptor already closed, aborting`, inside
`cargo test --workspace` on CI runners. Observed three times in full-gate
CI contexts (never in the twenty runs above, never in two hundred isolated
`af-monitor` lib loops, never in one hundred fifty paired-test loops; once
in seven gdb-guarded iterations). The gdb catch (debug workflow
`debug-monitor-abort`, run 33477164350, log `gdb-7.log` in the run's
artifact) pins the shape: the `TcpListener` of
`a_refused_connection_fails_in_the_program` (fd 7) drops after its
descriptor was already closed by another thread, while a second session
sits inside `fork()`. Root cause open; the instrument
(`.github/workflows/debug-monitor-abort.yml`) is committed for the hunt.
Tracked as its own rohrpost ticket, per the note that predicted it.
