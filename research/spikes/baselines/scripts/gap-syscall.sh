#!/usr/bin/env bash
# gap-syscall.sh - does full PTRACE_SYSCALL have a gap at all?
#
# A monitor that stops the target at every system call sees every request
# that the target sends to the kernel. The question is whether an ordinary
# action can change the state of the machine without a system call.
#
# Two cases exist for an unprivileged target:
#
#   1. the vDSO. The kernel maps code into every process, so clock_gettime
#      and a few other calls return without entering the kernel;
#   2. a shared file mapping. A store instruction changes the content of a
#      file, and the kernel writes the page back with no write call.
#
# The workload does both and then the script compares the counts.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$SPIKE_DIR/results/gap-syscall.txt"
WORK="$SPIKE_DIR/scratch/syscall"
ROUNDS=200000

rm -rf "$WORK"
mkdir -p "$WORK" "$SPIKE_DIR/results"

{
    printf '# the gap of full PTRACE_SYSCALL\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# rounds of clock_gettime in the workload: %s\n\n' "$ROUNDS"

    printf '## the run\n'
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall \
        --summary "$WORK/summary.txt" --histogram "$WORK/hist.txt" \
        -- "$SPIKE_DIR/bin/vdso_and_mmap" "$WORK/mapped-file.bin" "$ROUNDS" \
        2>"$WORK/target-stderr.txt"
    sed 's/^/  /' "$WORK/summary.txt"
    sed 's/^/  target: /' "$WORK/target-stderr.txt"

    printf '\n## case 1, the vDSO\n'
    printf 'the workload called clock_gettime %s times.\n' "$ROUNDS"
    printf 'the tracer counted:\n'
    python3 "$SPIKE_DIR/scripts/annotate-histogram.py" "$WORK/hist.txt" \
        clock_gettime gettimeofday time getcpu | sed 's/^/  /'

    printf '\n## case 2, a shared file mapping\n'
    printf 'the workload closed the descriptor and then changed the file\n'
    printf 'through the mapping. The file now holds:\n'
    printf '  %s\n' "$(head -c 64 "$WORK/mapped-file.bin" | tr -d '\0')"
    printf 'the tracer counted:\n'
    python3 "$SPIKE_DIR/scripts/annotate-histogram.py" "$WORK/hist.txt" \
        write pwrite64 writev msync mmap openat | sed 's/^/  /'

    printf '\n## the ordinary calls, to show that nothing else is missing\n'
    python3 "$SPIKE_DIR/scripts/annotate-histogram.py" "$WORK/hist.txt" |
        sed 's/^/  /'
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
