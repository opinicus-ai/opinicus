#!/usr/bin/env bash
#
# The complete gate of the repository.
#
# One script runs every check the project's documents promise: fmt, clippy,
# the workspace tests, the release build, the policy pack's own tests, the
# e2e suite, the quiet-check of the interruption budget, the Landlock
# pack/floor drift guard, the threat-ledger checker, and the supply-chain
# checks (cargo-deny: advisories, bans, licenses, sources; cargo-audit). A
# person or a continuous-integration job runs this script; a non-zero exit
# means one of the promises is broken.
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

# The supply-chain checks of [af-11]: known vulnerabilities and unmaintained
# crates, the no-network ban list, licenses, and crate sources. Missing
# tools fail the gate with the install command — a check that silently
# skips is not a check.
step "supply chain (cargo-deny advisories/bans/licenses/sources, cargo-audit)"
SUPPLY_CHAIN_TOOLS_MISSING=0
for tool in cargo-deny cargo-audit; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'gate: %s is not installed; install it with: cargo install %s --locked\n' \
            "$tool" "$tool" >&2
        SUPPLY_CHAIN_TOOLS_MISSING=1
    fi
done
[ "$SUPPLY_CHAIN_TOOLS_MISSING" -eq 0 ] || exit 2
cargo deny check advisories bans licenses sources
cargo audit --deny warnings

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

step "benign gate"
research/bypass/benign-gate.sh

step "count-rules (Landlock pack/floor drift guard)"
python3 research/spikes/landlock/tests/count-rules.py

step "threat-ledger check"
python3 research/threats/check.py

step "gate green"
printf 'every check of the complete gate passed\n'
