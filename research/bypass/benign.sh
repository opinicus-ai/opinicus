#!/usr/bin/env bash
# The benign corpus of [af-1]: a scripted normal dev session that must never
# trigger a question. Usage: benign.sh <mode>   (write-only | all-opens | off)
#
# PASS requires: the firewall returns the exit code of the session (0), no
# policy decision of a level above allow fired, the corpus ran to the end,
# and — since [af-3] — the session received zero agent tags. A normal dev
# session is not an agent session, and a false agent tag is worse than no
# tag. The corpus runs with the agent markers of the ambient environment as
# they are: a lone marker below the tagging line stays quiet, which is the
# quiet rule of identity, not a scrubbed environment.
#
# Since [af-4] the corpus also counts quarantines and tamper facts.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
MODE="$1"
OUT="$DIR/results/benign-$MODE"
rm -rf "$OUT"
mkdir -p "$OUT"

WORK="$REPO/tmp/bypass/benign-$MODE"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

# The corpus is one shared script, so the bypass harness and the in-process
# sensor spike of [af-2] measure the same session.
install -m 0755 "$DIR/corpus.sh" corpus.sh

set +e
"$FW" run --retention all --approve deny --syscall-filter "$MODE" --trace "$OUT/trace.jsonl" \
    -- bash corpus.sh >"$OUT/corpus.out" 2>"$OUT/fw.err"
FW_EXIT=$?
set -e

SESSION_EXIT=$(grep -o '"exit_code":[0-9]*' "$OUT/trace.jsonl" | tail -1 | cut -d: -f2)
QUESTIONS=$(python3 - "$OUT/trace.jsonl" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    if e.get("type") == "policy_decision":
        d = e.get("verdict", {}).get("decision")
        if d in ("approval_required", "deny", "terminate"):
            n += 1
print(n)
PY
)
AGENT_TAGS=$(python3 - "$OUT/trace.jsonl" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    if e.get("agent") is not None:
        n += 1
    if e.get("type") == "session_start" and e.get("meta", {}).get("detection") is not None:
        n += 1
print(n)
PY
)
NOTES=$(grep -c '"type": *"policy_decision"' "$OUT/trace.jsonl" || true)
# Since [af-4]: a quarantine is the most expensive question there is, and the
# gate of M4 is the negative test. A normal session must produce zero.
QUARANTINES=$(grep -c '"type": *"quarantine_started"' "$OUT/trace.jsonl" || true)
TAMPERS=$(grep -c '"type": *"tamper"' "$OUT/trace.jsonl" || true)

echo "mode=$MODE fw_exit=$FW_EXIT session_exit=$SESSION_EXIT questions=$QUESTIONS agent_tags=$AGENT_TAGS decision_events=$NOTES quarantines=$QUARANTINES tamper_events=$TAMPERS"
if [ "$FW_EXIT" = "0" ] && [ "$QUESTIONS" = "0" ] && [ "$AGENT_TAGS" = "0" ] && [ "$QUARANTINES" = "0" ]; then
    echo "PASS: the corpus ran clean with zero questions, zero agent tags and zero quarantines"
    echo "mode=$MODE questions=$QUESTIONS agent_tags=$AGENT_TAGS quarantines=$QUARANTINES fw_exit=$FW_EXIT" >> "$DIR/results/benign-summary.txt"
else
    echo "FAIL: the corpus triggered something; look in $OUT"
    echo "mode=$MODE questions=$QUESTIONS agent_tags=$AGENT_TAGS quarantines=$QUARANTINES fw_exit=$FW_EXIT FAIL" >> "$DIR/results/benign-summary.txt"
    exit 1
fi
