#!/usr/bin/env bash
# gap-inprocess.sh - the in-process gap of the shipping exec-only monitor.
#
# THE CENTRAL MEASUREMENT OF THIS SPIKE.
#
# The firewall stops a new program at PTRACE_EVENT_EXEC. An action inside a
# program that already runs starts no new program, so that stop never happens.
#
# The workload is one Python process. It removes a directory tree, it removes
# one file, and it opens a TCP connection to a listener that it starts itself.
# It starts no new program at all. Every path is inside the scratch directory
# of this spike, so nothing outside the spike can change.
#
# The run uses --approve deny. That is the strictest answer the firewall can
# give. If the actions still complete, the firewall never had a chance to
# judge them.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd -- "$SPIKE_DIR/../../.." && pwd)"
FIREWALL="$REPO_DIR/target/release/agent-firewall"
OUT="$SPIKE_DIR/results/gap-inprocess.txt"
WORK="$SPIKE_DIR/scratch/inprocess"
TRACE="$SPIKE_DIR/results/inprocess-trace.jsonl"
MARKER="$SPIKE_DIR/results/inprocess-marker.json"

rm -rf "$WORK"
mkdir -p "$WORK" "$SPIKE_DIR/results"
rm -f "$TRACE" "$MARKER"

{
    printf '# the in-process gap of the exec-only monitor\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# firewall: %s\n' "$("$FIREWALL" --version)"
    printf '# command: agent-firewall run --approve deny --trace T -- '
    printf 'python3 inproc_gap.py\n\n'

    printf '## the run\n'
    set +e
    "$FIREWALL" run --approve deny --trace "$TRACE" -- \
        python3 "$SPIKE_DIR/workloads/inproc_gap.py" "$WORK" "$MARKER" \
        >"$WORK/stdout.txt" 2>"$WORK/stderr.txt"
    status=$?
    set -e
    printf 'exit status of the firewall: %s\n' "$status"
    printf 'standard error of the session:\n'
    sed 's/^/  /' "$WORK/stderr.txt" | head -20

    printf '\n## did the actions complete?\n'
    if [ -f "$MARKER" ]; then
        printf 'the marker file exists, so the workload ran to the end:\n'
        sed 's/^/  /' "$MARKER"
    else
        printf 'THE MARKER FILE IS MISSING. The workload did not finish.\n'
    fi
    printf 'the removed tree still exists: '
    if [ -e "$WORK/tree-to-remove" ]; then printf 'yes\n'; else printf 'no\n'; fi
    printf 'the removed file still exists: '
    if [ -e "$WORK/single-file-to-unlink.txt" ]; then
        printf 'yes\n'
    else
        printf 'no\n'
    fi

    printf '\n## what the trace holds\n'
    if [ -f "$TRACE" ]; then
        printf 'events in the trace: %s\n' "$(wc -l <"$TRACE")"
        printf 'event kinds:\n'
        python3 - "$TRACE" <<'PY' | sed 's/^/  /'
import json
import sys

kinds = {}
with open(sys.argv[1]) as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        key = event.get("kind") or event.get("type") or sorted(event)[0]
        if isinstance(key, dict):
            key = sorted(key)[0]
        kinds[str(key)] = kinds.get(str(key), 0) + 1
for key, count in sorted(kinds.items()):
    print(f"{key}: {count}")
PY
        printf '\nthe whole trace:\n'
        sed 's/^/  /' "$TRACE"
    else
        printf 'no trace file was written\n'
    fi

    printf '\n## does the trace name any of the three actions?\n'
    printf 'The session_start line holds the capability report of the '
    printf 'firewall.\n'
    printf 'That text names a connection and a socket, so the search '
    printf 'skips it.\n'
    for needle in unlink rmtree remove delete connect socket tcp \
        tree-to-remove single-file-to-unlink; do
        count=0
        if [ -f "$TRACE" ]; then
            count="$(grep -v '"type":"session_start"' "$TRACE" |
                grep -c -i -- "$needle" || true)"
        fi
        printf '  %-24s lines in the trace: %s\n' "$needle" "$count"
    done

    # -----------------------------------------------------------------
    # The contrast. The same workload under a full system call tracer.
    # -----------------------------------------------------------------
    printf '\n## the contrast: the same workload under full PTRACE_SYSCALL\n'
    rm -rf "$WORK"
    mkdir -p "$WORK"
    "$SPIKE_DIR/bin/ptrace_full" --mode syscall \
        --summary "$SPIKE_DIR/results/inprocess-syscall.summary" \
        --histogram "$SPIKE_DIR/results/inprocess-syscall.hist" \
        -- python3 "$SPIKE_DIR/workloads/inproc_gap.py" "$WORK" \
        "$WORK/marker.json" >/dev/null 2>&1
    sed 's/^/  /' "$SPIKE_DIR/results/inprocess-syscall.summary"
    printf 'the calls that matter:\n'
    python3 "$SPIKE_DIR/scripts/annotate-histogram.py" \
        "$SPIKE_DIR/results/inprocess-syscall.hist" \
        unlink unlinkat rmdir connect socket execve openat | sed 's/^/  /'

    # -----------------------------------------------------------------
    # A second contrast. The same workload under LD_PRELOAD.
    # -----------------------------------------------------------------
    printf '\n## the contrast: the same workload under LD_PRELOAD\n'
    rm -rf "$WORK"
    mkdir -p "$WORK"
    preload_log="$SPIKE_DIR/results/inprocess-preload.log"
    : >"$preload_log"
    AFW_PRELOAD_LOG="$preload_log" "$SPIKE_DIR/wrappers/preload-wrap.sh" \
        python3 "$SPIKE_DIR/workloads/inproc_gap.py" "$WORK" \
        "$WORK/marker.json" >/dev/null 2>&1
    printf 'lines in the preload log: %s\n' "$(wc -l <"$preload_log")"
    printf 'unlink lines: %s\n' "$(grep -c '^unlink' "$preload_log" || true)"
    printf 'connect lines: %s\n' "$(grep -c '^connect' "$preload_log" || true)"
    printf 'connect and unlink lines, if any:\n'
    grep -E '^(unlink|connect)' "$preload_log" | sed 's/^/  /' ||
        printf '  (none)\n'
    printf 'Note: the system call tracer above counted the removal calls of\n'
    printf 'the same workload. The interposer wraps unlink, and Python uses\n'
    printf 'unlinkat for a tree. A wrapper set that is not complete is a\n'
    printf 'fourth gap of this mechanism.\n'
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
