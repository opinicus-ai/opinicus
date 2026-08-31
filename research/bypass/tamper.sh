#!/usr/bin/env bash
# The tamper gate of [af-4]: do the seeded tamper techniques of the harness
# fire every time, and does the quarantine flow hold them?
#
# Four seeded techniques, one per sensed shape:
#
#   kill-monitor   a signal to the monitor itself          (filter holds it)
#   escape-setsid  a descendant that leaves the session     (graph flags it)
#   respawn        a killed program that comes back         (monitor knows)
#   strip-preload  a child with no sensor preload           (launcher knows)
#
# PASS requires, for every technique: the trace holds a `tamper` event, a
# rule matched it, and — where the rule carries `quarantine: true` — the
# session saw a quarantine and a ruling. The detach is a report instead,
# because normal tooling makes the same shape (`git maintenance --detach`)
# and the interruption budget wins over severity.
#
# The negative side of the gate is research/bypass/benign.sh: zero
# quarantines on a normal session, in all three filter modes.
#
# Usage: tamper.sh            (writes results/tamper.md)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
BIN="$DIR/bin"
SENSOR="$REPO/research/spikes/inprocess/libafsensor.so"
OUT="$DIR/results/tamper"
rm -rf "$OUT"
mkdir -p "$OUT"

"$DIR/techniques/build.sh" >/dev/null
"$DIR/../spikes/inprocess/build.sh" >/dev/null

TABLE="$DIR/results/tamper.md"
header() {
    printf '| technique | command | fw exit | fact events | rule matches | quarantines | rulings | verdict |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- |\n'
}

# Counts one fact of a trace. $1 = trace, $2 = jq-free python expression.
count() {
    python3 - "$1" "$2" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    if eval(sys.argv[2]):  # noqa: S307 - a fixed expression of this script
        n += 1
print(n)
PY
}

# Runs one technique under the product posture and prints its table row.
# $1 = name, $2 = expect-quarantine (yes|no), $3 = the event kind that
# carries the sensed fact, $4 = trace path, rest = command.
run_technique() {
    local name="$1" expect_quarantine="$2" fact_kind="$3" trace="$4"; shift 4
    local scratch
    scratch="$(dirname "$trace")"
    mkdir -p "$scratch"
    set +e
    (cd "$scratch" && timeout 25 env ${ENV_EXTRA[@]+"${ENV_EXTRA[@]}"} "$FW" run \
        --retention all --approve deny --trace "$trace" -- "$@" \
        >"$scratch/out.txt" 2>"$scratch/err.txt")
    local fw_exit=$?
    set -e

    local tamper matched quarantines rulings
    tamper=$(count "$trace" "e.get('type')=='$fact_kind'")
    matched=$(count "$trace" "e.get('type')=='policy_decision' and any(m.get('rule_id','').startswith('tamper.') for m in e.get('verdict',{}).get('matches',[]))")
    quarantines=$(grep -c '"type": *"quarantine_started"' "$trace" || true)
    rulings=$(grep -c '"type": *"quarantine_resolved"' "$trace" || true)

    local verdict=ok
    if [ "$tamper" -lt 1 ] || [ "$matched" -lt 1 ]; then verdict=FIRE-FAILED; fi
    if [ "$expect_quarantine" = yes ] && { [ "$quarantines" -lt 1 ] || [ "$rulings" -lt 1 ]; }; then
        verdict=QUARANTINE-FAILED
    fi
    if [ "$expect_quarantine" = no ] && [ "$quarantines" -ne 0 ]; then verdict=BUDGET-FAILED; fi

    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
        "$name" "$*" "$fw_exit" "$tamper" "$matched" "$quarantines" "$rulings" "$verdict"
}

{
    header

    # 1. The monitor kill. The filter holds the signal before it runs, the
    #    tamper rule quarantines, and the deny of the harness refuses the
    #    call: the monitor lives, the technique sees EPERM.
    ENV_EXTRA=()
    run_technique kill-monitor yes signal_send "$OUT/kill-monitor/trace.jsonl" "$BIN/kill-monitor" marker.txt

    # 2. The escape. The graph flags the detached descendant; the rule
    #    reports it, because git maintenance makes the same shape on a
    #    normal session and the budget wins over severity.
    ENV_EXTRA=()
    run_technique escape-setsid no tamper "$OUT/escape-setsid/trace.jsonl" "$BIN/escape-setsid" marker.txt

    # 3. The respawn loop. The first run is denied by the built-in pack, the
    #    monitor kills it, and every following round is a sensed fact that
    #    quarantines the tree.
    ENV_EXTRA=()
    run_technique respawn yes tamper "$OUT/respawn/trace.jsonl" "$BIN/respawn" 3

    # 4. The stripped preload. The launcher carries the sensor of [af-2],
    #    and the child starts with no copy of it.
    ENV_EXTRA=("LD_PRELOAD=$SENSOR" "AF_SENSOR_TRACE=$OUT/strip-sensor.jsonl" \
               "AF_SENSOR_REG=$OUT/strip-sensor.reg" "AF_SENSOR_SESSION=af4-strip")
    run_technique strip-preload yes tamper "$OUT/strip-preload/trace.jsonl" "$BIN/strip-preload" marker.txt
} | tee "$TABLE"

PASS=$(grep -c '| ok |' "$TABLE" || true)
FAIL=$(grep -cE 'FIRE-FAILED|QUARANTINE-FAILED|BUDGET-FAILED' "$TABLE" || true)
echo
echo "tamper gate: $PASS of $((PASS + FAIL)) seeded techniques fired as specified"
[ "$FAIL" -eq 0 ]
