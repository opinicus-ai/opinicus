#!/usr/bin/env bash
# Splits the cost of a monitor into two parts: the fixed cost of one session
# and the cost of one new process. Both parts come from files that other
# scripts wrote, so this script only does arithmetic that a reader can check.
#
#   fixed cost   = startup cost with the monitor - startup cost with none
#   marginal cost = (workload with the monitor - workload with none - fixed)
#                   / number of new processes in the workload
#
# W1 starts 301 processes (1 shell and 300 runs of /bin/true).
# W3 starts 121 processes (1 shell and 60 runs each of /bin/cat and /bin/grep).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$HERE/results"
BENCH="$RESULTS/bench.txt"
STARTUP="$RESULTS/startup-cost.txt"
OUT="$RESULTS/per-exec.txt"

for file in "$BENCH" "$STARTUP"; do
    if [ ! -f "$file" ]; then
        printf 'missing %s; run ./run-all.sh first\n' "$file" >&2
        exit 1
    fi
done

# Reads the median of one workload under one section heading of bench.txt.
bench_ms() {
    awk -v section="$1" -v workload="$2" '
        $0 ~ /^### / { in_section = ($0 == "### " section) }
        in_section && $0 ~ ("^" workload) {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^median_ms=/) { split($i, p, "="); print p[2]; exit }
            }
        }' "$BENCH"
}

# Reads one median from startup-cost.txt, in microseconds.
startup_us() {
    awk -v label="$1" '
        index($0, label) == 1 {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^median_us=/) { split($i, p, "="); print p[2]; exit }
            }
        }' "$STARTUP"
}

base_w1="$(bench_ms 'baseline (no monitor)' 'W1')"
base_w3="$(bench_ms 'baseline (no monitor)' 'W3')"
base_start="$(startup_us 'no wrapper')"

{
    printf '# the fixed cost of a session and the cost of one new process\n'
    printf '# date: %s\n' "$(date --iso-8601=seconds)"
    printf '# baseline: W1=%s ms, W3=%s ms, session start=%s us\n' \
        "$base_w1" "$base_w3" "$base_start"
    printf '# W1 starts 301 processes, W3 starts 121 processes\n\n'
    printf '%-38s %-9s %-9s %-9s %-9s\n' \
        monitor fixed_ms w1_per_ms w3_per_ms share_fixed_w1
} >"$OUT"

report() {
    local label="$1" section="$2" startup_label="$3"
    local w1 w3 start

    w1="$(bench_ms "$section" 'W1')"
    w3="$(bench_ms "$section" 'W3')"
    start="$(startup_us "$startup_label")"

    awk -v label="$label" -v w1="$w1" -v w3="$w3" \
        -v base_w1="$base_w1" -v base_w3="$base_w3" \
        -v start="$start" -v base_start="$base_start" '
        BEGIN {
            fixed = (start - base_start) / 1000.0
            per_w1 = (w1 - base_w1 - fixed) / 301.0
            per_w3 = (w3 - base_w3 - fixed) / 121.0
            share = 100.0 * fixed / (w1 - base_w1)
            printf "%-38s %-9.1f %-9.3f %-9.3f %-9.1f\n",
                label, fixed, per_w1, per_w3, share
        }' >>"$OUT"
}

report 'exec-only ptrace (shipping monitor)' \
    'exec-only ptrace (the shipping monitor)' 'exec-only ptrace (shipping monitor)'
report 'event-only ptrace (own tracer)' \
    'event-only ptrace (own tracer, control)' 'event-only ptrace (own tracer)'
report 'full PTRACE_SYSCALL (own tracer)' \
    'full PTRACE_SYSCALL (own tracer)' 'full PTRACE_SYSCALL (own tracer)'
report 'LD_PRELOAD interposition' \
    'LD_PRELOAD interposition' 'LD_PRELOAD interposition'
report 'proc polling, 10 ms' \
    'proc polling, 10 ms' 'proc polling, 10 ms'

{
    printf '\n# how to read this\n'
    printf '# fixed_ms       cost of one session, whatever the workload is\n'
    printf '# w1_per_ms      cost of one new process, from W1\n'
    printf '# w3_per_ms      cost of one new process, from W3\n'
    printf '# share_fixed_w1 how much of the W1 overhead is the fixed cost\n'
} >>"$OUT"

cat "$OUT"
printf '\nwritten to %s\n' "$OUT"
