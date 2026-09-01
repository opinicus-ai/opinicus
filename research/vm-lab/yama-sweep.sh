#!/usr/bin/env bash
# The yama sweep inside the disposable lab: the full hostile-matrix
# measurement of [af-12], run where turning kernel.yama.ptrace_scope up
# cannot latch anything but the VM.
#
# Usage:
#   research/vm-lab/yama-sweep.sh [rounds]      # default 1
#
# The sweep records the HOST's scope before and after and fails if it
# moved — the whole contract of the lab in one assertion. Inside the VM
# the sweep installs the build tools, builds the workspace, and runs
# research/bypass/hostile.sh (which walks scopes 0-3 itself; one-way
# inside the VM is fine, the VM dies afterwards).
set -euo pipefail

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

ROUNDS="${1:-1}"
HOST_YAMA=/proc/sys/kernel/yama/ptrace_scope

BEFORE="$(cat "$HOST_YAMA")"
printf 'vm-lab: host yama ptrace_scope before: %s (must be unchanged after)\n' "$BEFORE"

# The host-untouched assertion runs even when a round fails: it is the
# contract of the lab, and a failed sweep is exactly when the user needs
# the proof.
host_scope_check() {
    local after; after="$(cat "$HOST_YAMA" 2>/dev/null || printf '?')"
    printf 'vm-lab: host yama ptrace_scope after: %s\n' "$after"
    if [ "$after" != "$BEFORE" ]; then
        printf 'vm-lab: HOST SCOPE MOVED (%s -> %s) — the lab contract is broken\n' "$BEFORE" "$after" >&2
        exit 1
    fi
    printf 'vm-lab: host untouched\n'
}
trap host_scope_check EXIT

for round in $(seq 1 "$ROUNDS"); do
    printf 'vm-lab: yama sweep round %d of %d\n' "$round" "$ROUNDS"
    RESEARCH_VM_LAB=1 "$LAB_DIR/vm-run.sh" sh -c '
        set -euo pipefail
        echo "vm: $(uname -r), yama=$(cat /proc/sys/kernel/yama/ptrace_scope)"
        dnf -q install -y gcc git python3 tar make perl golang >/dev/null 2>&1 || true
        curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal >/dev/null
        . "$HOME/.cargo/env"
        cd /root/opinicus
        cargo build --release 2>&1 | tail -1
        research/bypass/hostile.sh | tee /root/artifacts/hostile-round.'"$round"'.txt
    '
done
printf 'vm-lab: matrices in work/artifacts/\n'
