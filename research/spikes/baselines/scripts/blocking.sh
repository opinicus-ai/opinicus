#!/usr/bin/env bash
# blocking.sh - can each mechanism stop an action, or does it only watch?
#
# The action is always the same and it is harmless: a program writes a marker
# file inside the scratch directory of this spike. A mechanism that can block
# leaves the marker file missing. A mechanism that can only watch leaves the
# marker file written.
#
# The /proc poller has no test here, because the mechanism gives the
# supervisor no point at which it holds the target. The poller learns about a
# process after the process runs, and gap-polling.sh measures that it usually
# learns nothing at all.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
FIREWALL="$REPO_DIR/target/release/agent-firewall"
OUT="$SPIKE_DIR/results/blocking.txt"
WORK="$SPIKE_DIR/scratch/blocking"

rm -rf "$WORK"
mkdir -p "$WORK" "$SPIKE_DIR/results"

report() {
    local name="$1"
    local marker="$2"

    if [ -e "$marker" ]; then
        printf '%-40s marker=written   result=ONLY WATCHED\n' "$name"
    else
        printf '%-40s marker=MISSING   result=BLOCKED\n' "$name"
    fi
}

{
    printf '# can the mechanism stop an action?\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# the action: a program writes a marker file in the scratch '
    printf 'directory\n\n'

    # -----------------------------------------------------------------
    # The control. No monitor, so the marker must appear.
    # -----------------------------------------------------------------
    printf '## control, no monitor\n'
    "$SPIKE_DIR/bin/marker_libc" "$WORK/control-marker.txt" >/dev/null 2>&1 ||
        true
    report "no monitor" "$WORK/control-marker.txt"

    # -----------------------------------------------------------------
    # LD_PRELOAD. The wrapper returns an error and never calls the real
    # function.
    # -----------------------------------------------------------------
    printf '\n## LD_PRELOAD, the wrapper refuses the open\n'
    env LD_PRELOAD="$SPIKE_DIR/bin/libafwpreload.so" \
        AFW_PRELOAD_LOG="$WORK/preload.log" \
        AFW_PRELOAD_DENY="blocked-marker" \
        "$SPIKE_DIR/bin/marker_libc" "$WORK/blocked-marker-preload.txt" \
        >/dev/null 2>&1 || true
    report "LD_PRELOAD deny" "$WORK/blocked-marker-preload.txt"
    printf 'the log holds:\n'
    grep -E '^DENY' "$WORK/preload.log" | sed 's/^/  /' || printf '  (none)\n'

    printf '\n## LD_PRELOAD, the same deny against a static program\n'
    env LD_PRELOAD="$SPIKE_DIR/bin/libafwpreload.so" \
        AFW_PRELOAD_LOG="$WORK/preload.log" \
        AFW_PRELOAD_DENY="blocked-marker" \
        "$SPIKE_DIR/bin/marker_static" "$WORK/blocked-marker-static.txt" \
        >/dev/null 2>&1 || true
    report "LD_PRELOAD deny, static target" \
        "$WORK/blocked-marker-static.txt"

    # -----------------------------------------------------------------
    # Full PTRACE_SYSCALL. The tracer changes the call number at the entry
    # stop, so the kernel never runs the call.
    # -----------------------------------------------------------------
    printf '\n## full PTRACE_SYSCALL, the tracer refuses openat\n'
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall --deny openat \
        --summary "$WORK/ptrace-deny.summary" \
        -- "$SPIKE_DIR/bin/marker_libc" \
        "$WORK/blocked-marker-ptrace.txt" >/dev/null 2>&1 || true
    report "PTRACE_SYSCALL deny openat" "$WORK/blocked-marker-ptrace.txt"
    sed 's/^/  /' "$WORK/ptrace-deny.summary"

    printf '\n## full PTRACE_SYSCALL against the static program\n'
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall --deny openat \
        --summary "$WORK/ptrace-deny-static.summary" \
        -- "$SPIKE_DIR/bin/marker_static" \
        "$WORK/blocked-marker-ptrace-static.txt" >/dev/null 2>&1 || true
    report "PTRACE_SYSCALL deny, static target" \
        "$WORK/blocked-marker-ptrace-static.txt"
    sed 's/^/  /' "$WORK/ptrace-deny-static.summary"

    # -----------------------------------------------------------------
    # Exec-only ptrace, the shipping monitor. A rule of this spike matches
    # the program, and the firewall stops it at the exec stop.
    # -----------------------------------------------------------------
    printf '\n## exec-only ptrace, the shipping monitor with a spike rule\n'
    printf 'the rule file: policies/spike-blocking.yaml\n'
    "$FIREWALL" run --approve deny \
        --policy "$SPIKE_DIR/policies/spike-blocking.yaml" \
        -- "$SPIKE_DIR/bin/marker_libc" \
        "$WORK/blocked-marker-firewall.txt" \
        >"$WORK/firewall-stdout.txt" 2>"$WORK/firewall-stderr.txt" || true
    report "agent-firewall deny at exec" "$WORK/blocked-marker-firewall.txt"
    printf 'what the firewall said:\n'
    sed 's/^/  /' "$WORK/firewall-stderr.txt" | head -20

    printf '\n## the same monitor against a program with no rule\n'
    "$FIREWALL" run --approve deny \
        --policy "$SPIKE_DIR/policies/spike-blocking.yaml" \
        -- "$SPIKE_DIR/bin/marker_libc" "$WORK/allowed-marker.txt" \
        >/dev/null 2>&1 || true
    report "agent-firewall, no rule matches" "$WORK/allowed-marker.txt"

    printf '\n## the rule file passes its own tests\n'
    "$FIREWALL" policy test --no-builtin-policies \
        --policy "$SPIKE_DIR/policies/spike-blocking.yaml" 2>&1 |
        sed 's/^/  /'
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
