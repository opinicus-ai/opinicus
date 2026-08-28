#!/usr/bin/env bash
# bench-all.sh - measures the cost of every mechanism with the shared harness.
#
# Every row uses research/bench/bench.sh with the same number of runs, so the
# numbers can be compared with the numbers that are already in the research.
#
# Usage: bench-all.sh [RUNS]
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
BENCH="$REPO_DIR/research/bench/bench.sh"
FIREWALL="$REPO_DIR/target/release/agent-firewall"
RUNS="${1:-7}"
OUT="$SPIKE_DIR/results/bench.txt"

mkdir -p "$SPIKE_DIR/results" "$SPIKE_DIR/scratch"

if [ ! -x "$FIREWALL" ]; then
    printf 'bench-all.sh: build the release binary first:\n' >&2
    printf '  (cd %s && cargo build --release)\n' "$REPO_DIR" >&2
    exit 1
fi

run_row() {
    local label="$1"
    shift
    printf '\n### %s\n' "$label" | tee -a "$OUT"
    "$BENCH" --runs "$RUNS" -- "$@" 2>/dev/null | tee -a "$OUT"
}

: >"$OUT"
{
    printf '# cost of the cheap monitoring mechanisms\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# kernel: %s\n' "$(uname -r)"
    printf '# runs for each workload: %s\n' "$RUNS"
} | tee -a "$OUT"

printf '\n### baseline (no monitor)\n' | tee -a "$OUT"
"$BENCH" --runs "$RUNS" 2>/dev/null | tee -a "$OUT"

run_row "proc polling, 10 ms" "$SPIKE_DIR/bin/procpoll" --period-ms 10 --
run_row "proc polling, 50 ms" "$SPIKE_DIR/bin/procpoll" --period-ms 50 --
run_row "proc polling, 200 ms" "$SPIKE_DIR/bin/procpoll" --period-ms 200 --

rm -f "$SPIKE_DIR/scratch/preload-bench.log"
run_row "LD_PRELOAD interposition" "$SPIKE_DIR/wrappers/preload-wrap.sh"
printf 'preload log lines: %s\n' \
    "$(wc -l <"$SPIKE_DIR/scratch/preload-bench.log" 2>/dev/null || echo 0)" |
    tee -a "$OUT"

run_row "exec-only ptrace (the shipping monitor)" \
    "$FIREWALL" run --approve allow --

run_row "full PTRACE_SYSCALL (own tracer)" \
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall --

run_row "event-only ptrace (own tracer, control)" \
    "$SPIKE_DIR/bin/ptrace_full" --mode events --

printf '\nwritten to %s\n' "$OUT"
