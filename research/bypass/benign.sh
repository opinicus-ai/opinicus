#!/usr/bin/env bash
# The benign corpus of [af-1]: a scripted normal dev session that must never
# trigger a question. Usage: benign.sh <mode>   (write-only | all-opens | off)
#
# PASS requires: the firewall returns the exit code of the session (0), no
# policy decision of a level above allow fired, and the corpus ran to the end.
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

cat > corpus.sh <<'EOF'
set -e
git init -q .
git config user.email probe@example.com
git config user.name probe
echo hello > README.md
git add README.md
git commit -qm "first"
git log --oneline
git status --short
# The cargo crate is created and built OUTSIDE the repository: cargo new
# registers a new crate into any workspace it finds by walking upward, and
# it rewrites that root manifest. A standalone directory in /tmp cannot
# pollute the repository workspace; the built binary is copied back.
CRATE="$(mktemp -d /tmp/af-corpus.XXXXXX)"
cargo new --offline -q "$CRATE/tool"
(cd "$CRATE/tool" && cargo build --offline -q)
mkdir tool
cp "$CRATE/tool/target/debug/tool" tool/tool
./tool/tool
rm -rf "$CRATE"
mkdir web && (cd web && npm init -y >/dev/null 2>&1 && npm --version >/dev/null)
python3 -c 'print("corpus", 6 * 7)'
find . -name '*.md' | sort
grep -r hello README.md
EOF

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
NOTES=$(grep -c '"type": *"policy_decision"' "$OUT/trace.jsonl" || true)

echo "mode=$MODE fw_exit=$FW_EXIT session_exit=$SESSION_EXIT questions=$QUESTIONS decision_events=$NOTES"
if [ "$FW_EXIT" = "0" ] && [ "$QUESTIONS" = "0" ]; then
    echo "PASS: the corpus ran clean with zero questions"
    echo "mode=$MODE questions=$QUESTIONS fw_exit=$FW_EXIT" >> "$DIR/results/benign-summary.txt"
else
    echo "FAIL: the corpus triggered something; look in $OUT"
    echo "mode=$MODE questions=$QUESTIONS fw_exit=$FW_EXIT FAIL" >> "$DIR/results/benign-summary.txt"
    exit 1
fi
