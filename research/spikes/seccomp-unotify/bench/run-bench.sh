#!/usr/bin/env bash
# Runs the shared benchmark harness against the spike in every configuration.
#
# The harness is research/bench/bench.sh. Every approach in this research uses
# it, so the numbers can be compared directly with the ptrace numbers in
# docs/RESEARCH.md.
#
# Usage: bench/run-bench.sh [RUNS]
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$SPIKE_DIR/../../bench/bench.sh"
RUNS="${1:-7}"

if [ ! -x "$HARNESS" ]; then
    printf 'run-bench.sh: the harness %s is missing\n' "$HARNESS" >&2
    exit 2
fi

# The harness makes its work directory with mktemp. TMPDIR keeps that work
# inside the spike directory.
mkdir -p "$SPIKE_DIR/work/bench"
export TMPDIR="$SPIKE_DIR/work/bench"

cd "$SPIKE_DIR"
make --no-print-directory all >/dev/null

printf '=== baseline, no monitor ===\n'
"$HARNESS" --runs "$RUNS"

printf '\n=== (a) the filter traps only execve and execveat ===\n'
"$HARNESS" --runs "$RUNS" -- "$SPIKE_DIR/bin/afw-unotify" --filter=exec --

printf '\n=== (b) the filter traps the full set of Part 1 ===\n'
"$HARNESS" --runs "$RUNS" -- "$SPIKE_DIR/bin/afw-unotify" --filter=full --

printf '\n=== (c) the full set, and the supervisor does not read the memory ===\n'
"$HARNESS" --runs "$RUNS" -- "$SPIKE_DIR/bin/afw-unotify" --filter=full \
    --no-read-args --

printf '\n=== (d) the full set, and every allowed openat is emulated ===\n'
printf '    this is the only configuration that reads arguments safely\n'
"$HARNESS" --runs "$RUNS" -- "$SPIKE_DIR/bin/afw-unotify" --filter=full \
    --allow=emulate --

printf '\n=== (e) the content set: the full set plus write, writev and sendto ===\n'
printf '    this is what it costs to see the data of an action, and not\n'
printf '    only the name of the object\n'
"$HARNESS" --runs "$RUNS" -- "$SPIKE_DIR/bin/afw-unotify" --filter=io --
