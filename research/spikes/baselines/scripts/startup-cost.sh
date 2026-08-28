#!/usr/bin/env bash
# startup-cost.sh - the fixed cost of one supervised session.
#
# Every wrapper must start, read its own configuration and set up the
# monitoring before the target runs. A workload of 15 ms shows that fixed cost
# as if it were overhead. This script separates the two: it measures a run of
# /bin/true, where the target does almost nothing.
#
# Usage: startup-cost.sh [RUNS]
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
FIREWALL="$REPO_DIR/target/release/agent-firewall"
RUNS="${1:-11}"
OUT="$SPIKE_DIR/results/startup-cost.txt"

mkdir -p "$SPIKE_DIR/results"

median_ms() {
    sort -n | awk '{ v[NR] = $1 } END {
        if (NR == 0) { print "0"; exit }
        if (NR % 2) { print v[(NR + 1) / 2] }
        else { print (v[NR / 2] + v[NR / 2 + 1]) / 2 }
    }'
}

measure() {
    local label="$1"
    shift
    local run start end
    local value

    "$@" /bin/true >/dev/null 2>&1 || true
    value="$(
        for run in $(seq 1 "$RUNS"); do
            start="$(date +%s%N)"
            "$@" /bin/true >/dev/null 2>&1 || true
            end="$(date +%s%N)"
            printf '%s\n' "$(((end - start) / 1000))"
        done | median_ms
    )"
    printf '%-42s median_us=%s runs=%s\n' "$label" "$value" "$RUNS"
}

{
    printf '# fixed cost of one session, target is /bin/true\n'
    printf '# date: %s\n' "$(date -Is)"

    measure "no wrapper" env
    measure "proc polling, 10 ms" "$SPIKE_DIR/bin/procpoll" --period-ms 10 --
    measure "LD_PRELOAD interposition" "$SPIKE_DIR/wrappers/preload-wrap.sh"
    measure "event-only ptrace (own tracer)" \
        "$SPIKE_DIR/bin/ptrace_full" --mode events --
    measure "full PTRACE_SYSCALL (own tracer)" \
        "$SPIKE_DIR/bin/ptrace_full" --mode syscall --
    measure "exec-only ptrace (shipping monitor)" \
        "$FIREWALL" run --approve allow --
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
