#!/usr/bin/env bash
# The correlation gate of [af-5]: do the discrepancy rules fire on the bypass
# corpus, and does the benign corpus stay at zero?
#
# The engine is `agent-firewall correlate`: it compares the sensor's own
# record (trace + registration record, the expected view) with the monitor's
# trace (the observed view) and raises every disagreement as a discrepancy
# event, which the rules of policies/correlation.yaml judge.
#
# Bypass side, one seeded technique per discrepancy kind:
#
#   sensor-freeze   a frozen sensor inside a living process   (silent subtree)
#   sensor-blind    the sensor's descriptors closed mid-run   (silent + contradicted)
#   sensor-unlink   the sensor's library deleted, then spawns (unreported spawn)
#   rawsys          file and network around libc              (contradicted)
#   strip-preload   a child with no preload at all            (control: M4 owns it)
#
# sensor-freeze is the measured product defense of this gate: the monitor's
# wait loop continues a tracee that stopped itself, so a whole-process
# SIGSTOP cannot hold a session open and the child runs through its freeze
# (verified by its marker). The row records the defense; PASS requires the
# freeze to raise nothing at all.
#
# The negative side is the benign corpus of [af-1] under the sensor, in all
# three filter modes. PASS requires: every seeded technique raises its
# discrepancy, and every benign run raises none. A rule ships only on the
# second number being zero — that is the exit gate of M5.
#
# Usage: correlate.sh           (writes results/correlation.md)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
BIN="$DIR/bin"
SENSOR_SRC="$REPO/research/spikes/inprocess"
OUT="$DIR/results/correlation"
rm -rf "$OUT"
mkdir -p "$OUT"

"$DIR/techniques/build.sh" >/dev/null
"$SENSOR_SRC/build.sh" >/dev/null

# Counts the JSON findings of one correlate run that carry a rule match.
# $1 = the correlate JSON output, $2 = a python expression over a finding f.
count() {
    python3 - "$1" "$2" <<'PY'
import json, sys
n = 0
with open(sys.argv[1]) as fh:
    answer = json.load(fh)
for f in answer.get("findings", []):
    if eval(sys.argv[2]):  # noqa: S307 - a fixed expression of this script
        n += 1
print(n)
PY
}

# Runs one command under the product posture with the sensor active, then
# correlates the two views. $1 = name, rest = command.
run_pair() {
    local name="$1"; shift
    local scratch="$OUT/$name"
    mkdir -p "$scratch"
    cp "$SENSOR_SRC/libafsensor.so" "$scratch/libafsensor.so"
    set +e
    (cd "$scratch" && timeout 60 env \
        LD_PRELOAD="$scratch/libafsensor.so" \
        AF_SENSOR_TRACE="$scratch/sensor.jsonl" \
        AF_SENSOR_REG="$scratch/sensor.reg" \
        AF_SENSOR_SESSION="af5-$name" \
        "$FW" run --retention all --approve deny --syscall-filter write-only \
        --trace "$scratch/trace.jsonl" -- "$@" \
        >"$scratch/out.txt" 2>"$scratch/err.txt")
    local fw_exit=$?
    set -e
    "$FW" correlate "$scratch/trace.jsonl" \
        --sensor "$scratch/sensor.jsonl" --reg "$scratch/sensor.reg" \
        --emit "$scratch/discrepancy.jsonl" --json >"$scratch/correlate.json"
    echo "$fw_exit"
}

# Runs the benign corpus in one filter mode with the sensor active, then
# correlates. $1 = mode.
benign_pair() {
    local mode="$1"
    local scratch="$OUT/benign-$mode"
    mkdir -p "$scratch"
    cp "$SENSOR_SRC/libafsensor.so" "$scratch/libafsensor.so"
    set +e
    (cd "$scratch" && env \
        LD_PRELOAD="$scratch/libafsensor.so" \
        AF_SENSOR_TRACE="$scratch/sensor.jsonl" \
        AF_SENSOR_REG="$scratch/sensor.reg" \
        AF_SENSOR_SESSION="af5-benign-$mode" \
        "$DIR/benign.sh" "$mode" >"$scratch/benign.out" 2>&1)
    local benign_exit=$?
    set -e
    "$FW" correlate "$DIR/results/benign-$mode/trace.jsonl" \
        --sensor "$scratch/sensor.jsonl" --reg "$scratch/sensor.reg" \
        --emit "$scratch/discrepancy.jsonl" --json >"$scratch/correlate.json"
    echo "$benign_exit"
}

TABLE="$DIR/results/correlation.md"
RULES="correlation.sensor.silent-subtree correlation.action.contradicted correlation.spawn.unreported"

# One row per rule: firings on the bypass corpus versus firings on the benign
# corpus. The engine is the same for both; only the session differs.
row() {
    local rule="$1" label="$2"; shift 2
    local bypass=0 benign=0 detail=""
    for json in "$OUT"/*/correlate.json; do
        local n
        n=$(count "$json" "any(m.get('rule_id') == '$rule' for m in f.get('matches', []))")
        local run
        run="$(basename "$(dirname "$json")")"
        if [[ "$run" == benign-* ]]; then
            benign=$((benign + n))
        else
            bypass=$((bypass + n))
        fi
        if [ "$n" -gt 0 ]; then
            detail="$detail $run:$n"
        fi
    done
    local verdict
    if [ "$benign" -eq 0 ]; then
        verdict=quiet-on-benign
    else
        verdict=BUDGET-FAILED
    fi
    printf '| %s | %s | %s | %s | %s |\n' "$label" "$bypass" "$benign" "${detail:- -}" "$verdict"
}

{
    echo "# The correlation gate of [af-5]"
    echo
    echo "Engine: \`agent-firewall correlate\` (af-correlate + the rules of"
    echo "\`policies/correlation.yaml\`). Machine of the run: see"
    echo "research/bypass/FINDINGS.md. Regenerate with \`./correlate.sh\`."
    echo
    echo "| rule | bypass corpus firings | benign corpus firings | where | verdict |"
    echo "| --- | ---: | ---: | --- | --- |"

    # ---- bypass side ------------------------------------------------------
    EXIT_FREEZE=$(run_pair sensor-freeze "$BIN/sensor-freeze" marker.txt)
    EXIT_BLIND=$(run_pair sensor-blind "$BIN/sensor-blind" marker.txt)
    EXIT_UNLINK=$(run_pair sensor-unlink "$BIN/sensor-unlink" "$OUT/sensor-unlink/libafsensor.so" marker.txt)
    # A local listener for the rawsys connect, as orchestrate.py builds it.
    mkdir -p "$OUT/rawsys"
    python3 - "$OUT/rawsys" <<'PY' &
import socket, sys, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(4)
with open(sys.argv[1] + "/port", "w") as fh:
    fh.write(str(srv.getsockname()[1]))
def serve():
    for _ in range(4):
        try:
            conn, _ = srv.accept()
            conn.recv(1024)
            conn.close()
        except OSError:
            return
threading.Thread(target=serve, daemon=True).start()
import time
time.sleep(60)
PY
    LISTENER=$!
    sleep 0.3
    PORT=$(cat "$OUT/rawsys/port")
    EXIT_RAWSYS=$(run_pair rawsys "$BIN/rawsys" "$PORT" "$OUT/rawsys/marker.txt")
    kill "$LISTENER" 2>/dev/null || true
    EXIT_STRIP=$(run_pair strip-preload "$BIN/strip-preload" marker.txt)

    # ---- benign side ------------------------------------------------------
    BENIGN_WO=$(benign_pair write-only)
    BENIGN_AO=$(benign_pair all-opens)
    BENIGN_OFF=$(benign_pair off)

    # The research telemetry of the refused comparison: write-intent opens
    # with --compare-write-opens on the write-only corpus run. This is the
    # measurement that refused the write comparison; the number stays in the
    # table so it stays regenerable.
    "$FW" correlate "$DIR/results/benign-write-only/trace.jsonl" \
        --sensor "$OUT/benign-write-only/sensor.jsonl" --reg "$OUT/benign-write-only/sensor.reg" \
        --compare-write-opens --json >"$OUT/benign-write-only/correlate-writes.json"
    RESEARCH_WRITES=$(python3 - "$OUT/benign-write-only/correlate-writes.json" <<'PY'
import json, sys
answer = json.load(open(sys.argv[1]))
print(answer.get("counts", {}).get("findings", 0))
PY
)

    # ---- the ledger -------------------------------------------------------
    row correlation.sensor.silent-subtree "silent sensor subtree"
    row correlation.action.contradicted "contradicted action"
    row correlation.spawn.unreported "unreported spawn"
    # The measured null kinds, for the record: no rule ships for them.
    UNSEEN_BYPASS=$(python3 - "$OUT" <<'PY'
import json, pathlib, sys
n = 0
for path in pathlib.Path(sys.argv[1]).rglob("correlate.json"):
    answer = json.loads(path.read_text())
    n += sum(1 for f in answer.get("findings", []) if f["kind"] == "spawn_reported_unseen")
print(n)
PY
)
    echo
    echo "spawn_reported_unseen on the bypass corpus: $UNSEEN_BYPASS finding(s); no rule ships for it — the exec stop is a kernel guarantee for the whole tree."
    echo
    echo "research telemetry, refused by the gate: write-intent open comparison on the benign corpus (write-only, --compare-write-opens): $RESEARCH_WRITES finding(s) in one normal session; the product compares connections only."
    echo
    echo "technique exits: freeze=$EXIT_FREEZE blind=$EXIT_BLIND unlink=$EXIT_UNLINK rawsys=$EXIT_RAWSYS strip=$EXIT_STRIP; benign exits: $BENIGN_WO/$BENIGN_AO/$BENIGN_OFF (write-only/all-opens/off)."
} | tee "$TABLE"

# The gate: every seeded discrepancy fired its rule on the bypass side, the
# strip control stayed dark for correlation, and the benign corpus produced
# zero firings of every rule.
python3 - "$OUT" "$TABLE" <<'PY'
import json, pathlib, sys

out = pathlib.Path(sys.argv[1])
answers = {
    path.parent.name: json.loads(path.read_text())
    for path in out.rglob("correlate.json")
}

def fired(run, kind):
    return sum(
        1 for f in answers[run].get("findings", []) if f["kind"] == kind
    )

def rules(run, rule):
    return sum(
        1
        for f in answers[run].get("findings", [])
        for m in f.get("matches", [])
        if m["rule_id"] == rule
    )

problems = []
# The product defeats the freeze itself: the monitor continues a tracee that
# stopped itself, so the freeze must raise nothing and the child must have
# run through it.
if answers["sensor-freeze"].get("counts", {}).get("findings", 0):
    problems.append("sensor-freeze raised findings, but the monitor defeats the freeze")
marker = pathlib.Path(sys.argv[1]) / "sensor-freeze" / "marker.txt"
if "frozen-child" not in marker.read_text():
    problems.append("the frozen child never ran; the freeze row is not a measurement")
if not fired("sensor-blind", "sensor_silent_subtree"):
    problems.append("sensor-blind raised no sensor_silent_subtree")
if not fired("rawsys", "action_contradicted"):
    problems.append("rawsys raised no action_contradicted")
if not fired("sensor-unlink", "spawn_seen_unreported"):
    problems.append("sensor-unlink raised no spawn_seen_unreported")
for run in ("strip-preload",):
    if answers[run].get("counts", {}).get("findings", 0):
        problems.append(f"{run} raised findings the live tamper rule does not own")
for run, mode in (
    ("benign-write-only", "write-only"),
    ("benign-all-opens", "all-opens"),
    ("benign-off", "off"),
):
    for rule in (
        "correlation.sensor.silent-subtree",
        "correlation.action.contradicted",
        "correlation.spawn.unreported",
    ):
        if rules(run, rule):
            problems.append(f"{run} fired {rule}: the budget refuses")

if problems:
    for problem in problems:
        print(f"GATE FAILED: {problem}")
    sys.exit(1)
print("correlation gate passed: every seeded discrepancy fired, the benign corpus fired nothing")
PY
