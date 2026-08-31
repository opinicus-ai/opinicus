#!/usr/bin/env bash
#
# The complete gate of the repository.
#
# One script runs every check the project's documents promise: fmt, clippy,
# the workspace tests, the release build, the policy pack's own tests, the
# e2e suite, the quiet-check of the interruption budget, the Landlock
# pack/floor drift guard, and the threat-ledger checker. A person or a
# continuous-integration job runs this script; a non-zero exit means one of
# the promises is broken.
#
# Usage:
#   scripts/gate.sh
#
# Environment:
#   AFW_NO_BUILD   Set to 1 to skip the release build and the sensor build.
#                  The binary must already exist (used by repeated runs).
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

BINARY="$ROOT/target/release/agent-firewall"
SENSOR="$ROOT/research/spikes/inprocess/libafsensor.so"

step() { printf '\n=== gate: %s ===\n' "$1"; }

step "cargo fmt --check"
cargo fmt --check

step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo test --workspace"
cargo test --workspace

if [ "${AFW_NO_BUILD:-0}" != "1" ]; then
    step "cargo build --release"
    cargo build --release
    step "build the in-process sensor"
    research/spikes/inprocess/build.sh
fi

[ -x "$BINARY" ] || { printf 'gate: %s is missing; build first\n' "$BINARY" >&2; exit 2; }
[ -f "$SENSOR" ] || { printf 'gate: %s is missing; run research/spikes/inprocess/build.sh\n' "$SENSOR" >&2; exit 2; }

step "policy check"
"$BINARY" policy check policies

step "policy test"
"$BINARY" policy test

step "e2e"
AFW_BIN="$BINARY" tests/e2e.sh --no-build

step "quiet-check"
research/bench/quiet-check.sh

step "count-rules (Landlock pack/floor drift guard)"
python3 research/spikes/landlock/tests/count-rules.py

step "threat-ledger check"
python3 research/threats/check.py

step "gate green"
printf 'every check of the complete gate passed\n'
