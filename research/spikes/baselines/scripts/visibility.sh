#!/usr/bin/env bash
# visibility.sh - can the monitored program see the monitor?
#
# The program under test prints the fields of /proc/self/status that name a
# supervisor, its own LD_PRELOAD variable and any injected library in
# /proc/self/maps. The script runs it with no monitor and then under each
# monitor, so that the difference is visible.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
FIREWALL="$REPO_DIR/target/release/agent-firewall"
OUT="$SPIKE_DIR/results/visibility.txt"

mkdir -p "$SPIKE_DIR/results"

{
    printf '# what a monitored program can learn about its monitor\n'
    printf '# date: %s\n\n' "$(date -Is)"

    printf '## no monitor\n'
    "$SPIKE_DIR/bin/selfcheck" no-monitor | sed 's/^/  /'

    printf '\n## under the shipping monitor, exec-only ptrace\n'
    "$FIREWALL" run --approve allow -- \
        "$SPIKE_DIR/bin/selfcheck" under-agent-firewall 2>/dev/null |
        sed 's/^/  /'

    printf '\n## under full PTRACE_SYSCALL\n'
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall --summary /dev/null -- \
        "$SPIKE_DIR/bin/selfcheck" under-ptrace-syscall | sed 's/^/  /'

    printf '\n## under LD_PRELOAD\n'
    AFW_PRELOAD_LOG="$SPIKE_DIR/scratch/visibility-preload.log" \
        "$SPIKE_DIR/wrappers/preload-wrap.sh" \
        "$SPIKE_DIR/bin/selfcheck" under-ld-preload | sed 's/^/  /'

    printf '\n## with a seccomp filter that the program installed on itself\n'
    "$SPIKE_DIR/bin/selfcheck" --install-seccomp with-seccomp-filter |
        sed 's/^/  /'

    printf '\n## the same read from a shell, to show how little it costs\n'
    printf 'command: while read -r line; do case "$line" in TracerPid*) '
    printf 'echo "$line";; esac; done < /proc/self/status\n'
    printf 'under the shipping monitor:\n'
    "$FIREWALL" run --approve allow -- /bin/sh -c \
        'while read -r line; do case "$line" in TracerPid*) echo "$line";; esac; done < /proc/self/status' \
        2>/dev/null | sed 's/^/  /'
    printf 'with no monitor:\n'
    /bin/sh -c \
        'while read -r line; do case "$line" in TracerPid*) echo "$line";; esac; done < /proc/self/status' |
        sed 's/^/  /'
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
