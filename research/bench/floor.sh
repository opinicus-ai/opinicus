#!/usr/bin/env bash
# Overhead of the kernel floor on the shared benchmark (ML, 2026-08-31).
#
# The floor is enacted once per session, before the first program runs, and
# the kernel decides every access with no supervisor in the loop. The
# expected cost is the one-time build of the ruleset (about 300 rules, 1–2 ms
# on this machine) and nothing else. This script measures the product with
# the floor on and with the floor off against the same baseline, so the
# number that matters is the difference between the two product rows.
#
# Usage: research/bench/floor.sh [RUNS]
set -euo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
RUNS="${1:-7}"
FW="$REPO/target/release/agent-firewall"

if [ ! -x "$FW" ]; then
    printf 'floor.sh: build the workspace first: cargo build --release\n' >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

printf '== baseline, no firewall\n'
"$DIR/bench.sh" --runs "$RUNS"

printf '\n== product, kernel floor off\n'
"$DIR/bench.sh" --runs "$RUNS" -- "$FW" run --approve deny --landlock off \
    --trace "$WORK/off.jsonl" --

printf '\n== product, kernel floor on (the default)\n'
"$DIR/bench.sh" --runs "$RUNS" -- "$FW" run --approve deny \
    --trace "$WORK/on.jsonl" --
