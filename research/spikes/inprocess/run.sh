#!/usr/bin/env bash
# The self-check of the in-process sensor of M2: build the shim, run a small
# workload under it, prove the trace is schema-valid af-core events, show
# the registration record, and prove the silence checker can fire.
#
# The matrix re-run lives in research/bypass/run.sh (preload pass); the
# benign corpus in run-corpus.sh; the overhead in bench.sh. FINDINGS.md
# holds the numbers.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../../.." && pwd)"
FW="$REPO/target/release/agent-firewall"

"$DIR/build.sh" >/dev/null
WORK="$REPO/tmp/spikes/inprocess-demo"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

export LD_PRELOAD="$DIR/libafsensor.so"
export AF_SENSOR_SESSION="af2-selfcheck"
export AF_SENSOR_TRACE="$WORK/trace.jsonl"
export AF_SENSOR_REG="$WORK/sensor.reg"

# 1. A workload that touches every event family: exec, file open, file read
#    capture, delete, rename, connect-less network path, dlopen, env.
python3 - <<'PY'
import ctypes, os, subprocess
open("note.txt", "w").write("DROP DATABASE sensor_selfcheck\n")
print(open("note.txt").read())
os.unlink("note.txt")
open("a.txt", "w").write("a")
os.rename("a.txt", "b.txt")
os.environ["AF2_DEMO"] = "yes"
ctypes.CDLL(None)  # dlopen of the program itself
subprocess.run(["/bin/true"])
PY
echo "hello on stdin" | cat >/dev/null

unset LD_PRELOAD AF_SENSOR_TRACE AF_SENSOR_REG AF_SENSOR_SESSION
echo "--- events:"
python3 "$DIR/reader.py" "$WORK/trace.jsonl" --gain
echo "--- registration record (first and last 3 lines):"
head -3 "$WORK/sensor.reg"
tail -3 "$WORK/sensor.reg"

# 2. The silence checker must fire on a stopped instance: a process that
#    spoke, then froze while its pid lives on.
export LD_PRELOAD="$DIR/libafsensor.so"
export AF_SENSOR_SESSION="af2-silence"
export AF_SENSOR_TRACE="$WORK/silence.jsonl"
export AF_SENSOR_REG="$WORK/silence.reg"
SILENT_PID=""
python3 -c "open('f.txt','w'); import time; time.sleep(60)" & SILENT_PID=$!
sleep 2
kill -STOP "$SILENT_PID"
sleep 4
unset LD_PRELOAD AF_SENSOR_TRACE AF_SENSOR_REG AF_SENSOR_SESSION
echo "--- silence positive control (a stopped instance must fire):"
if python3 "$DIR/reader.py" "$WORK/silence.jsonl" --reg "$WORK/silence.reg"; then
    echo "FAIL: the silence checker did not fire on a stopped instance"
    kill -CONT "$SILENT_PID" 2>/dev/null || true
    kill "$SILENT_PID" 2>/dev/null || true
    exit 1
fi
kill -CONT "$SILENT_PID" 2>/dev/null || true
kill "$SILENT_PID" 2>/dev/null || true
wait "$SILENT_PID" 2>/dev/null || true
echo "self-check passed"
