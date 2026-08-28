#!/usr/bin/env bash
# syscall-rate.sh - how much does one system call stop cost?
#
# The benchmark gives the extra milliseconds of a workload. This script
# counts the stops of the same workload, so that the overhead becomes a cost
# for each stop. Another thread can compare a seccomp notification against
# this number.
#
# Usage: syscall-rate.sh
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$SPIKE_DIR/results/syscall-rate.txt"
WORK="$SPIKE_DIR/scratch/rate"

rm -rf "$WORK"
mkdir -p "$WORK/files" "$SPIKE_DIR/results"

for index in $(seq 1 500); do
    printf 'line one\nline two\nline three\n' >"$WORK/files/file-$index.txt"
done

cat >"$WORK/w1-exec.sh" <<'W1'
#!/bin/sh
index=0
while [ "$index" -lt 300 ]; do
    /bin/true
    index=$((index + 1))
done
W1

cat >"$WORK/w2-file.sh" <<W2
#!/bin/sh
cat "$WORK/files"/*.txt >/dev/null
grep -l "line two" "$WORK/files"/*.txt >/dev/null
W2

cat >"$WORK/w3-mixed.sh" <<W3
#!/bin/sh
index=0
while [ "\$index" -lt 60 ]; do
    /bin/cat "$WORK/files/file-1.txt" >/dev/null
    /bin/grep -q "line one" "$WORK/files/file-2.txt"
    index=\$((index + 1))
done
W3

chmod +x "$WORK"/w*.sh

field() {
    sed -n "s/.*$1=\([^ ]*\).*/\1/p" "$2"
}

median_ms() {
    sort -n | awk '{ v[NR] = $1 } END {
        if (NR % 2) { print v[(NR + 1) / 2] }
        else { print (v[NR / 2] + v[NR / 2 + 1]) / 2 }
    }'
}

time_plain() {
    local script="$1"
    local run start end

    /bin/sh "$script" >/dev/null 2>&1
    for run in $(seq 1 7); do
        start="$(date +%s%N)"
        /bin/sh "$script" >/dev/null 2>&1
        end="$(date +%s%N)"
        printf '%s\n' "$(((end - start) / 1000000))"
    done | median_ms
}

time_traced() {
    local script="$1"
    local run start end

    for run in $(seq 1 7); do
        start="$(date +%s%N)"
        "$SPIKE_DIR/bin/ptrace_full" --mode syscall \
            --summary "$WORK/last.summary" -- /bin/sh "$script" \
            >/dev/null 2>&1
        end="$(date +%s%N)"
        printf '%s\n' "$(((end - start) / 1000000))"
    done | median_ms
}

{
    printf '# the cost of one system call stop\n'
    printf '# date: %s\n\n' "$(date -Is)"
    printf '%-10s %-12s %-12s %-10s %-12s %s\n' \
        workload plain_ms traced_ms stops extra_ms us_per_stop
    for name in w1-exec w2-file w3-mixed; do
        plain="$(time_plain "$WORK/$name.sh")"
        traced="$(time_traced "$WORK/$name.sh")"
        stops="$(field syscall_stops "$WORK/last.summary")"
        calls="$(field syscalls "$WORK/last.summary")"
        awk -v n="$name" -v p="$plain" -v t="$traced" -v s="$stops" \
            -v c="$calls" 'BEGIN {
                extra = t - p
                printf "%-10s %-12s %-12s %-10s %-12s %.2f (calls %s)\n",
                    n, p, t, s, extra, (s ? 1000.0 * extra / s : 0), c
            }'
    done
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
