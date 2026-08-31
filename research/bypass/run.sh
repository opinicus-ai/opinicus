#!/usr/bin/env bash
# The bypass harness of [af-1]: what do the two shipping sensors hold, see,
# and miss? Runs the full matrix and the benign corpus, then classifies.
#
#   ./run.sh              # everything: baseline, builtin, probe, preload, benign
#   ./run.sh --quick      # builtin and probe at the default mode only
#
# The preload pass is the [af-2] re-run: the product posture plus the
# in-process sensor of research/spikes/inprocess/. It answers which silent
# cells the sensor moves to seen; the sensor itself never holds.
#
# Results land in results/ (regenerable; not committed). The classified
# matrix is results/matrix.json; classify.py prints the table. FINDINGS.md
# holds the numbers that the documents cite.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

"$DIR/techniques/build.sh" >/dev/null
"$DIR/../spikes/inprocess/build.sh" >/dev/null
python3 orchestrate.py --preload
python3 classify.py | tee results/matrix.md
for mode in write-only all-opens off; do
    ./benign.sh "$mode" || true
done
