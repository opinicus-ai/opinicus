#!/usr/bin/env bash
# Counts the supervisor stops of each configuration.
#
# The timing script says how much a configuration costs. This script says
# why: it counts how many times the kernel woke the supervisor. The three
# workloads are the same as the ones of research/bench/bench.sh.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HYBRID="$SPIKE_DIR/build/afw-hybrid"
WORK="$SPIKE_DIR/work/count"

rm -rf "$WORK"
mkdir -p "$WORK/files"
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

for config in "$@"; do
    for workload in w1-exec w2-file w3-mixed; do
        line="$("$HYBRID" --config "$config" --quiet --stats -- \
            /bin/sh "$WORK/$workload.sh" 2>&1 >/dev/null | grep '^stats' || true)"
        printf '%-10s %s\n' "$workload" "$line"
    done
done
