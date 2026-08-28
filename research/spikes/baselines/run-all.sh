#!/usr/bin/env bash
# run-all.sh - builds the spike and runs every measurement.
#
#   ./run-all.sh            the normal run, 7 runs for each benchmark
#   ./run-all.sh 15         more runs, for a quieter number
#
# Every result goes to results/ as a text file. FINDINGS.md quotes those
# files.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
RUNS="${1:-7}"

cd "$SPIKE_DIR"

printf '==> building the tools and the workloads\n'
make --no-print-directory

if [ ! -x "$REPO_DIR/target/release/agent-firewall" ]; then
    printf '==> building the shipping monitor\n'
    (cd "$REPO_DIR" && cargo build --release)
fi

printf '\n==> part 1a: the cost of each mechanism (%s runs)\n' "$RUNS"
./scripts/bench-all.sh "$RUNS" >/dev/null

printf '==> part 1b: the fixed cost of one session\n'
./scripts/startup-cost.sh 11 >/dev/null

printf '==> part 1b2: the fixed cost and the cost of one new process\n'
./scripts/per-exec.sh >/dev/null

printf '==> part 1c: the processor cost of polling\n'
./scripts/cpu-cost.sh 3 >/dev/null

printf '==> part 1d: the cost of one system call stop\n'
./scripts/syscall-rate.sh >/dev/null

printf '==> part 2a: the miss rate of polling\n'
./scripts/gap-polling.sh 5 >/dev/null

printf '==> part 2b: the structural gaps of LD_PRELOAD\n'
./scripts/gap-preload.sh >/dev/null

printf '==> part 2c: the in-process gap of the shipping monitor\n'
./scripts/gap-inprocess.sh >/dev/null

printf '==> part 2d: the gap of full PTRACE_SYSCALL\n'
./scripts/gap-syscall.sh >/dev/null

printf '==> part 2e: can each mechanism block, or only watch\n'
./scripts/blocking.sh >/dev/null

printf '==> part 3: can the target see the monitor\n'
./scripts/visibility.sh >/dev/null

printf '\n==> every result is in %s/results\n' "$SPIKE_DIR"
ls -1 results
