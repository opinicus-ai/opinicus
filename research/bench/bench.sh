#!/usr/bin/env bash
# Shared benchmark harness for the detection research.
#
# Every approach must use this harness, so that the numbers can be compared.
# The harness runs three fixed workloads under a wrapper command and prints
# the median wall-clock time of each one.
#
# Usage:
#   bench.sh                          # measures the workloads with no monitor
#   bench.sh -- ./my-monitor          # measures them under a monitor
#   bench.sh --runs 9 -- strace -f -o /dev/null
#
# The wrapper receives the workload command and its arguments. It must run
# that command and wait for it to end.
#
# Output is one line for each workload:
#   W1 exec       median_ms=123 runs=7
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

RUNS=7
WRAPPER=()

while [ $# -gt 0 ]; do
    case "$1" in
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --)
            shift
            WRAPPER=("$@")
            break
            ;;
        *)
            printf 'bench.sh: unknown option %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

# ---------------------------------------------------------------------------
# The workload data.
# ---------------------------------------------------------------------------

# W2 reads many small files. The files are made once, so the measurement
# counts the reads and not the writes.
FILE_DIR="$WORK_DIR/files"
mkdir -p "$FILE_DIR"
for index in $(seq 1 500); do
    printf 'line one\nline two\nline three\n' >"$FILE_DIR/file-$index.txt"
done

# ---------------------------------------------------------------------------
# The three workloads.
#
# W1 makes many processes. It measures the cost of an exec stop.
# W2 opens many files. It measures the cost of a file system call stop.
# W3 mixes both, so it is closer to real work of a coding agent.
# ---------------------------------------------------------------------------

cat >"$WORK_DIR/w1-exec.sh" <<'W1'
#!/bin/sh
index=0
while [ "$index" -lt 300 ]; do
    /bin/true
    index=$((index + 1))
done
W1

cat >"$WORK_DIR/w2-file.sh" <<W2
#!/bin/sh
cat "$FILE_DIR"/*.txt >/dev/null
grep -l "line two" "$FILE_DIR"/*.txt >/dev/null
W2

cat >"$WORK_DIR/w3-mixed.sh" <<W3
#!/bin/sh
index=0
while [ "\$index" -lt 60 ]; do
    /bin/cat "$FILE_DIR/file-1.txt" >/dev/null
    /bin/grep -q "line one" "$FILE_DIR/file-2.txt"
    index=\$((index + 1))
done
W3

chmod +x "$WORK_DIR"/w*.sh

# ---------------------------------------------------------------------------
# Measurement.
# ---------------------------------------------------------------------------

# Prints the median of the numbers that it reads from standard input.
median() {
    sort -n | awk '{ values[NR] = $1 }
        END {
            if (NR == 0) { print "0"; exit }
            if (NR % 2) { print values[(NR + 1) / 2] }
            else { print int((values[NR / 2] + values[NR / 2 + 1]) / 2) }
        }'
}

# Runs one workload the requested number of times and prints the median in
# milliseconds. A failed run stops the harness, because a monitor that breaks
# the workload must not report a good number.
measure() {
    local label="$1"
    local script="$2"
    local run
    local start
    local end

    # One warm run fills the page cache, so the first measured run is not
    # slower than the others for a reason that has nothing to do with the
    # monitor.
    if [ "${#WRAPPER[@]}" -gt 0 ]; then
        "${WRAPPER[@]}" /bin/sh "$script" >/dev/null 2>&1 || true
    else
        /bin/sh "$script" >/dev/null 2>&1 || true
    fi

    for run in $(seq 1 "$RUNS"); do
        start="$(date +%s%N)"
        if [ "${#WRAPPER[@]}" -gt 0 ]; then
            "${WRAPPER[@]}" /bin/sh "$script" >/dev/null 2>&1
        else
            /bin/sh "$script" >/dev/null 2>&1
        fi
        end="$(date +%s%N)"
        printf '%s\n' "$(( (end - start) / 1000000 ))"
    done | median | {
        read -r value
        printf '%-14s median_ms=%-8s runs=%s\n' "$label" "$value" "$RUNS"
    }
}

if [ "${#WRAPPER[@]}" -gt 0 ]; then
    printf 'wrapper: %s\n' "${WRAPPER[*]}"
else
    printf 'wrapper: (none, this is the baseline)\n'
fi

measure "W1 exec" "$WORK_DIR/w1-exec.sh"
measure "W2 file" "$WORK_DIR/w2-file.sh"
measure "W3 mixed" "$WORK_DIR/w3-mixed.sh"
