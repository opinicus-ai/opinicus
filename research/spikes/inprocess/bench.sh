#!/usr/bin/env bash
# Overhead of the in-process sensor of M2 on the shared benchmark.
#
# The wrapper form is the one every spike uses: the workload runs under a
# wrapper command that receives it. Here the wrapper is `env`, which puts
# the shim into the environment of the workload and of every child.
#
#   ./bench.sh              # baseline and shim, 7 runs each
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../../.." && pwd)"
WORK="$REPO/tmp/spikes/inprocess-bench"
rm -rf "$WORK"
mkdir -p "$WORK"

"$DIR/build.sh" >/dev/null
BENCH="$REPO/research/bench/bench.sh"

echo "== baseline (no sensor)"
"$BENCH" --runs 7 | tee "$WORK/baseline.txt"
echo
echo "== in-process sensor active"
env LD_PRELOAD="$DIR/libafsensor.so" \
    AF_SENSOR_SESSION="af2-bench" \
    AF_SENSOR_TRACE="$WORK/bench.jsonl" \
    AF_SENSOR_REG="$WORK/bench.reg" \
    "$BENCH" --runs 7 -- env \
    LD_PRELOAD="$DIR/libafsensor.so" \
    AF_SENSOR_SESSION="af2-bench" \
    AF_SENSOR_TRACE="$WORK/bench.jsonl" \
    AF_SENSOR_REG="$WORK/bench.reg" | tee "$WORK/sensor.txt"

echo
echo "== product posture plus sensor (the deployed shape of the preload pass)"
env LD_PRELOAD="$DIR/libafsensor.so" \
    AF_SENSOR_SESSION="af2-bench-fw" \
    AF_SENSOR_TRACE="$WORK/bench-fw.jsonl" \
    AF_SENSOR_REG="$WORK/bench-fw.reg" \
    "$BENCH" --runs 7 -- env \
    LD_PRELOAD="$DIR/libafsensor.so" \
    AF_SENSOR_SESSION="af2-bench-fw" \
    AF_SENSOR_TRACE="$WORK/bench-fw.jsonl" \
    AF_SENSOR_REG="$WORK/bench-fw.reg" \
    "$REPO/target/release/agent-firewall" run \
    --approve deny --syscall-filter write-only \
    --trace "$WORK/fw.jsonl" -- | tee "$WORK/sensor-fw.txt"

echo
echo "sensor trace events: $(grep -c . "$WORK/bench.jsonl" || true)"
echo "registered instances: $(grep -c sensor_register "$WORK/bench.reg" || true)"
