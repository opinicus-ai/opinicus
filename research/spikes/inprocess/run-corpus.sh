#!/usr/bin/env bash
# The benign corpus under the in-process sensor of M2 — the quiet gate.
#
# Part 1 runs the corpus with the sensor and no firewall, for the semantic
# gain: what fraction of the corpus's interesting actions the sensor reports
# that argv alone cannot describe.
#
# Part 2 runs the corpus under the full product posture with the sensor
# active (research/bypass/benign.sh with the shim in the environment), for
# the interruption budget: zero questions, plus the sensor-silence check,
# which must fire zero times.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../../.." && pwd)"
OUT="$DIR/results/corpus"
rm -rf "$OUT"
mkdir -p "$OUT"

"$DIR/build.sh" >/dev/null

# --- Part 1: the corpus under the sensor alone ---------------------------
WORK="$REPO/tmp/spikes/inprocess-corpus"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"
install -m 0755 "$REPO/research/bypass/corpus.sh" corpus.sh
env LD_PRELOAD="$DIR/libafsensor.so" \
    AF_SENSOR_SESSION="af2-corpus" \
    AF_SENSOR_TRACE="$OUT/sensor-only.jsonl" \
    AF_SENSOR_REG="$OUT/sensor-only.reg" \
    bash corpus.sh >/dev/null 2>&1
echo "== semantic gain (sensor only, no firewall):"
python3 "$DIR/reader.py" "$OUT/sensor-only.jsonl" --reg "$OUT/sensor-only.reg" --gain

# --- Part 2: the corpus under the product posture, sensor active ----------
for MODE in write-only all-opens off; do
    env LD_PRELOAD="$DIR/libafsensor.so" \
        AF_SENSOR_SESSION="af2-corpus-$MODE" \
        AF_SENSOR_TRACE="$OUT/sensor-$MODE.jsonl" \
        AF_SENSOR_REG="$OUT/sensor-$MODE.reg" \
        "$REPO/research/bypass/benign.sh" "$MODE"
done

echo "== sensor traces of the product runs (schema + silence):"
for MODE in write-only all-opens off; do
    python3 "$DIR/reader.py" "$OUT/sensor-$MODE.jsonl" --reg "$OUT/sensor-$MODE.reg" | tail -2
done
echo "corpus gate passed: zero questions, zero sensor silence, schema valid"
