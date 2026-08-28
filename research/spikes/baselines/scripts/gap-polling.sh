#!/usr/bin/env bash
# gap-polling.sh - how many processes does a /proc poller never see?
#
# The workload is W1 of the shared harness: a shell that runs /bin/true three
# hundred times. Each child lives for about half a millisecond, so most of
# them start and end between two polls.
#
# The ground truth comes from ptrace in event mode. The kernel reports a fork
# before the new process runs, so that count cannot miss a process.
#
# Usage: gap-polling.sh [REPEATS]
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPEATS="${1:-5}"
OUT="$SPIKE_DIR/results/gap-polling.txt"
WORK="$SPIKE_DIR/scratch/polling"

mkdir -p "$SPIKE_DIR/results" "$WORK"

# The same body as W1 of research/bench/bench.sh.
cat >"$WORK/w1-exec.sh" <<'W1'
#!/bin/sh
index=0
while [ "$index" -lt 300 ]; do
    /bin/true
    index=$((index + 1))
done
W1
chmod +x "$WORK/w1-exec.sh"

# A second workload with children that live long enough for a poller to have
# a chance. It shows where the mechanism starts to work.
cat >"$WORK/slow.sh" <<'SLOW'
#!/bin/sh
index=0
while [ "$index" -lt 20 ]; do
    /bin/sleep 0.05
    index=$((index + 1))
done
SLOW
chmod +x "$WORK/slow.sh"

field() {
    # Reads "key=value" from a summary line.
    sed -n "s/.*$1=\([^ ]*\).*/\1/p" "$2"
}

process_count() {
    find /proc -maxdepth 1 -regex '/proc/[0-9]+' 2>/dev/null | wc -l
}

# Runs one workload under the ground-truth tracer and under the poller at
# each period, and prints one table.
compare_workload() {
    local title="$1"
    local script="$2"
    local expected="$3"
    local tag="$4"
    local truth_total=0
    local truth_mean
    local repeat
    local value
    local period

    printf '## %s\n' "$title"
    for repeat in $(seq 1 "$REPEATS"); do
        "$SPIKE_DIR/bin/ptrace_full" --mode events \
            --summary "$WORK/truth-$repeat.summary" \
            -- /bin/sh "$script" >/dev/null 2>&1
        value="$(field processes "$WORK/truth-$repeat.summary")"
        truth_total=$((truth_total + value))
    done
    truth_mean=$((truth_total / REPEATS))
    printf 'ground truth from ptrace events: %s processes (expected %s)\n' \
        "$truth_mean" "$expected"

    printf '%-10s %-10s %-10s %-12s %-8s %s\n' \
        period seen missed miss_rate polls range
    for period in 10 50 200; do
        local seen_total=0
        local polls_total=0
        local seen_min=999999
        local seen_max=0
        local seen_mean
        local polls_mean
        local missed
        local rate

        for repeat in $(seq 1 "$REPEATS"); do
            "$SPIKE_DIR/bin/procpoll" --period-ms "$period" \
                --log "$WORK/$tag-poll-$period-$repeat.log" \
                --summary "$WORK/$tag-poll-$period-$repeat.summary" \
                -- /bin/sh "$script" >/dev/null 2>&1
            value="$(field seen_processes \
                "$WORK/$tag-poll-$period-$repeat.summary")"
            polls="$(field polls "$WORK/$tag-poll-$period-$repeat.summary")"
            seen_total=$((seen_total + value))
            polls_total=$((polls_total + polls))
            [ "$value" -lt "$seen_min" ] && seen_min="$value"
            [ "$value" -gt "$seen_max" ] && seen_max="$value"
        done
        seen_mean=$((seen_total / REPEATS))
        polls_mean=$((polls_total / REPEATS))
        missed=$((truth_mean - seen_mean))
        rate="$(awk -v m="$missed" -v t="$truth_mean" \
            'BEGIN { printf "%.1f%%", (t ? 100.0 * m / t : 0) }')"
        printf '%-10s %-10s %-10s %-12s %-8s min %s, max %s\n' \
            "${period}ms" "$seen_mean" "$missed" "$rate" "$polls_mean" \
            "$seen_min" "$seen_max"
    done
    printf '\n'
}

{
    printf '# the short-life gap of /proc polling\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# repeats for each period: %s\n' "$REPEATS"
    printf '# processes on the machine during the test: %s\n' \
        "$(process_count)"
    printf '\n'

    compare_workload \
        "W1 of the shared harness: 300 runs of /bin/true, each about 0.5 ms" \
        "$WORK/w1-exec.sh" "301 = 1 shell + 300 children" w1

    compare_workload \
        "a slower workload: 20 runs of /bin/sleep 0.05, each about 50 ms" \
        "$WORK/slow.sh" "21 = 1 shell + 20 children" slow

    printf '# every process that the 10 ms poller saw during one W1 run:\n'
    if [ -f "$WORK/w1-poll-10-1.log" ]; then
        cat "$WORK/w1-poll-10-1.log"
    fi
    printf '\n# the first lines that the 10 ms poller saw during one slow '
    printf 'run:\n'
    if [ -f "$WORK/slow-poll-10-1.log" ]; then
        head -6 "$WORK/slow-poll-10-1.log"
    fi
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
