#!/usr/bin/env bash
# Cost of the Landlock sandbox, through the shared harness.
#
# Every run has a time limit of 20 seconds. A sandbox makes operations fail,
# so a workload under a sandbox can stop. The limit makes sure that a stopped
# run gives no number instead of waiting for ever.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd -- "$HERE/../../.." && pwd)"
BENCH="$ROOT/research/bench/bench.sh"
LL="$HERE/bin/afw-landlock"

RUNS="${RUNS:-7}"
LIMIT=20

# The workloads run /bin/sh on a script in a temporary directory, they read
# files in that directory, and they write to /dev/null. These four grants are
# the minimum that lets every workload finish.
MIN=(--rx /usr --rx /etc --rw /tmp --rw /dev/null)

run() {
    printf '\n### %s\n' "$1"
    shift
    timeout 600 "$BENCH" --runs "$RUNS" --timeout "$LIMIT" "$@" 2>&1 || \
        printf 'this configuration gave no number\n'
}

printf 'Landlock benchmark. runs=%s per-run limit=%ss\n' "$RUNS" "$LIMIT"
printf 'ruleset build cost, printed by the launcher itself:\n'
timeout 20 "$LL" --stats "${MIN[@]}" -- /bin/true 2>&1 | sed 's/^/  minimal   /'
timeout 20 "$LL" --stats "${MIN[@]}" --ro "$HOME" --hide "$HOME/.ssh" -- /bin/true 2>&1 \
    | sed 's/^/  carve-out /'

run "baseline, no wrapper at all"

run "fork and exec only, no ruleset (the price of the launcher itself)" \
    -- "$LL" --no-sandbox --

run "minimal file ruleset (4 rules)" \
    -- "$LL" "${MIN[@]}" --

run "minimal ruleset plus TCP handled, no port allowed" \
    -- "$LL" "${MIN[@]}" --handle-net --

run "minimal ruleset plus the home carve-out (about 200 rules)" \
    -- "$LL" "${MIN[@]}" --ro "$HOME" --hide "$HOME/.ssh" --

run "everything Landlock has: fs, net and the signal scope" \
    -- "$LL" "${MIN[@]}" --handle-net --connect-tcp 443 --scope-signal --

# Write-xor-execute: /tmp is writable and no program may start from it. This
# is the ruleset that carries process.exec.from-temp.
run "write-xor-execute on /tmp" \
    -- "$LL" --rx /usr --rx /etc --rw-noexec /tmp --rw /dev/null --
