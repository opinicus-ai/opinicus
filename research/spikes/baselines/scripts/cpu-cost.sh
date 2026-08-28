#!/usr/bin/env bash
# cpu-cost.sh - the processor cost of the /proc poller.
#
# The cost of one poll depends on the number of processes on the machine, and
# not on the work of the target. The target is therefore /bin/sleep, which
# does nothing. The poller reports its own processor time, so the share of one
# core is a simple division.
#
# Usage: cpu-cost.sh [SECONDS]
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SECONDS_TO_RUN="${1:-3}"
OUT="$SPIKE_DIR/results/cpu-cost.txt"

mkdir -p "$SPIKE_DIR/results" "$SPIKE_DIR/scratch"

field() {
    sed -n "s/.*$1=\([^ ]*\).*/\1/p" "$2"
}

{
    printf '# processor cost of /proc polling\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# target: /bin/sleep %s, which uses no processor time\n' \
        "$SECONDS_TO_RUN"
    printf '# processes on the machine: %s\n\n' \
        "$( find /proc -maxdepth 1 -regex '/proc/[0-9]+' 2>/dev/null | wc -l)"

    printf '%-10s %-8s %-14s %-14s %-14s\n' \
        period polls self_cpu_ms ms_per_poll share_of_one_core
    for period in 10 50 200; do
        summary="$SPIKE_DIR/scratch/cpu-$period.summary"
        "$SPIKE_DIR/bin/procpoll" --period-ms "$period" \
            --summary "$summary" -- /bin/sleep "$SECONDS_TO_RUN" \
            >/dev/null 2>&1
        polls="$(field polls "$summary")"
        cpu="$(field self_cpu_ms "$summary")"
        wall="$(field wall_ms "$summary")"
        awk -v p="$period" -v n="$polls" -v c="$cpu" -v w="$wall" \
            'BEGIN {
                printf "%-10s %-8s %-14s %-14.2f %-14.1f%%\n",
                    p "ms", n, c, (n ? c / n : 0), (w ? 100.0 * c / w : 0)
            }'
    done
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
