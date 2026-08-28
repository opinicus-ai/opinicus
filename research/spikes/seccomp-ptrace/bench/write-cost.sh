#!/usr/bin/env bash
# Measures what a stop costs for a program that writes in small pieces.
#
# The three workloads of the shared harness read files and start programs.
# They do not write much. A database client or a script that prints line by
# line does, so this script measures that case on its own.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HYBRID="$SPIKE_DIR/build/afw-hybrid"
COUNT="${COUNT:-20000}"
RUNS="${RUNS:-5}"

median() {
    sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'
}

measure() {
    local label="$1"
    shift
    local run
    local start
    local end

    "$@" dd if=/dev/zero of=/dev/null bs=1 count="$COUNT" >/dev/null 2>&1 || true
    for run in $(seq 1 "$RUNS"); do
        start="$(date +%s%N)"
        "$@" dd if=/dev/zero of=/dev/null bs=1 count="$COUNT" >/dev/null 2>&1
        end="$(date +%s%N)"
        printf '%s\n' "$(((end - start) / 1000000))"
    done | median | {
        read -r value
        printf '%-34s median_ms=%s\n' "$label" "$value"
    }
}

printf 'a program that writes %s times, one byte each\n' "$COUNT"
measure "no monitor"
measure "config g (open for change)" "$HYBRID" --config g --quiet
measure "config w (write and sendto)" "$HYBRID" --config w --quiet
measure "config e (every system call)" "$HYBRID" --config e --quiet
