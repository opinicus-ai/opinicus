#!/usr/bin/env bash
# The fast benign gate of [af-10]: one corpus run, end to end, and the whole
# summary scanned.
#
# The benign corpus of [af-1] is the quiet test of the interruption budget:
# a normal dev session under the product posture must produce zero
# questions, zero agent tags and zero quarantines. research/bypass/run.sh
# exercises all three filter modes, but only after the full attack matrix —
# far too slow for scripts/gate.sh. This script runs ONE representative mode
# (write-only: the product default, and the mode the M4 detach regression
# fired on) end to end, and then refuses any FAIL anywhere in
# results/benign-summary.txt. That file is append-only and gitignored, and
# the M4 FAIL sat in it unnoticed precisely because nothing ever looked
# (the [af-10] lesson).
#
# Usage: research/bypass/benign-gate.sh    (from anywhere; seconds, not
#                                         minutes, when the cargo/npm
#                                         caches are warm)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY="$DIR/results/benign-summary.txt"

# One end-to-end corpus run at the representative mode. benign.sh exits
# non-zero when the session asked a question, grew an agent tag, saw a
# quarantine, or the firewall stopped the session, and it appends its
# result line to the summary either way.
"$DIR/benign.sh" write-only

# The whole summary must be free of FAIL. A FAIL recorded by any earlier
# run — benign.sh at any mode, run.sh, run-corpus.sh, correlate.sh, or a
# manual invocation — fails this gate until the summary is regenerated the
# honest way: run the corpus again, never edit the file.
if grep -n "FAIL" "$SUMMARY" 2>/dev/null; then
    printf 'benign gate: the benign summary holds FAIL lines (above); a normal session never fires — investigate the run, then regenerate %s\n' "$SUMMARY" >&2
    exit 1
fi
printf 'benign gate: the write-only corpus ran quiet; the summary holds no FAIL\n'
