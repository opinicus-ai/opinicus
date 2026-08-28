#!/usr/bin/env bash
# Runs a command with the LD_PRELOAD interposer active.
#
# Usage: preload-wrap.sh CMD [ARG...]
#
# AFW_PRELOAD_LOG selects the log file. The default is a file in the scratch
# directory of the spike, so that the wrapper always records something and the
# benchmark counts the true cost of the record.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

export LD_PRELOAD="$SPIKE_DIR/bin/libafwpreload.so"
export AFW_PRELOAD_LOG="${AFW_PRELOAD_LOG:-$SPIKE_DIR/scratch/preload-bench.log}"

mkdir -p -- "$(dirname -- "$AFW_PRELOAD_LOG")"

exec "$@"
