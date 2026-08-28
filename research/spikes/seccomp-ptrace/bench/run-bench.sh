#!/usr/bin/env bash
# Measures the cost of each filter configuration.
#
# The timing comes from the shared harness research/bench/bench.sh, so that
# the numbers can be compared with every other approach of the research.
#
# Usage:
#   ./bench/run-bench.sh                # every configuration, 7 runs
#   ./bench/run-bench.sh --runs 3       # a faster pass
#   ./bench/run-bench.sh --configs a,d  # only some configurations
#   ./bench/run-bench.sh --with-strace  # also the strace reference rows
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$SPIKE_DIR/../../bench/bench.sh"
HYBRID="$SPIKE_DIR/build/afw-hybrid"

RUNS=7
CONFIGS="x z a b c d e"
WITH_STRACE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --configs) CONFIGS="$(printf '%s' "$2" | tr ',' ' ')"; shift 2 ;;
        --with-strace) WITH_STRACE=1; shift ;;
        *) printf 'run-bench.sh: unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [ ! -x "$HYBRID" ]; then
    printf 'run-bench.sh: build the spike first with make\n' >&2
    exit 2
fi

describe() {
    case "$1" in
        x) printf 'af-monitor of today: ptrace exec events, no filter' ;;
        z) printf 'a filter that traces nothing' ;;
        a) printf 'execve and execveat' ;;
        b) printf 'execve, openat only when the flags ask for a change' ;;
        c) printf 'execve, every openat' ;;
        d) printf 'execve, openat, unlinkat, renameat2, connect' ;;
        e) printf 'no filter: PTRACE_SYSCALL on every system call' ;;
        f) printf 'the product filter: d without execve, exec comes from ptrace' ;;
        g) printf 'f, but openat only when the flags ask for a change' ;;
        w) printf 'write, writev, sendto, sendmsg, connect' ;;
    esac
}

printf '=== baseline ===\n'
"$HARNESS" --runs "$RUNS"

for config in $CONFIGS; do
    printf '\n=== config %s: %s ===\n' "$config" "$(describe "$config")"
    "$HARNESS" --runs "$RUNS" -- "$HYBRID" --config "$config" --quiet
done

if [ "$WITH_STRACE" -eq 1 ] && command -v strace >/dev/null; then
    printf '\n=== reference: strace -f -qq (full PTRACE_SYSCALL) ===\n'
    "$HARNESS" --runs "$RUNS" -- strace -f -qq -o /dev/null
    printf '\n=== reference: strace -f -qq --seccomp-bpf -e trace=execve ===\n'
    "$HARNESS" --runs "$RUNS" -- strace -f -qq --seccomp-bpf -e trace=execve -o /dev/null
fi
