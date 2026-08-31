#!/usr/bin/env bash
# The M3 gate of [af-3]: agent identity — detection, propagation, escape.
#
# Runs the three measurements of the milestone exit gate:
#   1. the fixture corpus: precision and recall (synthetic fixtures,
#      honestly labeled; no real coding agent is installed on this machine);
#   2. the escape fixture: a setsid/double-fork descendant under a tagged
#      agent root is flagged unlinked and keeps its tag;
#   3. the benign corpus: a normal dev session receives zero questions and
#      zero agent tags, in all three filter modes.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
OUT="$DIR/results"
mkdir -p "$OUT"
rm -rf "$OUT"/*

echo "== 1. the fixture corpus: precision and recall"
(cd "$REPO" && cargo test -p af-core --test identity_corpus -- --nocapture) 2>&1 | tee "$OUT/corpus.txt" | grep -E "identity corpus"

echo
echo "== 2. the escape fixture under the product"
"$REPO/research/bypass/techniques/build.sh" >/dev/null
ESCAPE="$REPO/research/bypass/bin/escape-setsid"
WORK="$REPO/tmp/detection/escape"
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"

run_escape() {
    local label="$1"; shift
    local expect_tag="$1"; shift
    local marker="marker-$label"
    local trace="trace-$label.jsonl"
    rm -f "$marker" "$trace"
    set +e
    env "$@" "$FW" run --retention all --trace "$trace" --approve deny -- "$ESCAPE" "$marker" \
        >"out-$label" 2>"err-$label"
    local fw_exit=$?
    set -e
    python3 - "$label" "$expect_tag" "$fw_exit" "$marker" "$trace" <<'PY'
import json, sys

label, expect_tag, fw_exit, marker, trace = sys.argv[1:]
effect = open(marker).read().count("escape-leaf")
events = [json.loads(l) for l in open(trace)]
unlinked = [e for e in events if e.get("type") == "process_unlinked"]
tagged = sum(1 for e in events if e.get("agent") is not None)
ok = True

if fw_exit != "0":
    print(f"  {label}: FAIL fw exit {fw_exit}"); ok = False
if effect < 1:
    print(f"  {label}: FAIL the leaf never ran"); ok = False
if not unlinked:
    print(f"  {label}: FAIL no process_unlinked event"); ok = False
for e in unlinked:
    tag = e.get("agent")
    if expect_tag == "yes" and tag is None:
        print(f"  {label}: FAIL the unlinked event carries no agent tag"); ok = False
    elif expect_tag == "no" and tag is not None:
        print(f"  {label}: FAIL an untagged session must not grow a tag"); ok = False
    elif tag is not None and tag.get("link") != "unlinked":
        print(f"  {label}: FAIL the unlinked event is not marked unlinked"); ok = False
    d = e.get("detach", {})
    if d.get("sid") == d.get("root_sid"):
        print(f"  {label}: FAIL the detach fact carries no session identifiers"); ok = False

if ok:
    print(f"  {label}: unlinked={len(unlinked)} tagged_events={tagged} effect={effect} "
          f"detach={unlinked[0].get('detach') if unlinked else None} "
          f"tag={(unlinked[0].get('agent') or {}).get('name') if unlinked else None}")
sys.exit(0 if ok else 1)
PY
    # The product's own readers must still read the trace with the new kinds.
    "$FW" tree "$trace" >/dev/null
    "$FW" replay "$trace" >/dev/null
}

# The agent-tagged run: the root is tagged through the environment marker
# (the binary itself is not an agent), the setsid leaf is flagged unlinked
# with the tag retained — unlinked, never foreign.
run_escape tagged yes CLAUDECODE=1
grep -q "agent session: claude-code" "err-tagged" || {
    echo "  tagged: FAIL the launcher did not tag the session"; exit 1; }

# The control: without a tag the escape is still flagged — the flag is a
# liveness fact of the tree, not a property of the identity.
run_escape plain no

# The daemon that never runs another program: its detachment becomes visible
# only at its own exit event. This is the behavior-03 (outlive) row of [af-1],
# the B.6 fact that nothing sensed before.
OUTLIVE="$REPO/research/bypass/bin/outlive"
rm -f outlive.marker outlive.jsonl
set +e
timeout 30 "$FW" run --retention all --trace outlive.jsonl --approve deny -- \
    "$OUTLIVE" outlive.marker >/dev/null 2>&1
OUTLIVE_EXIT=$?
set -e
if [ "$OUTLIVE_EXIT" = "0" ] && grep -q outlived outlive.marker \
    && python3 -c "
import json, sys
events = [json.loads(l) for l in open('outlive.jsonl')]
unlinked = [e for e in events if e.get('type') == 'process_unlinked']
assert unlinked, 'the daemon that called setsid was never flagged'
d = unlinked[0].get('detach', {})
assert d.get('sid') != d.get('root_sid'), 'no measured session identifiers'
print(f'  outlive: unlinked={len(unlinked)} detach={d}')
"; then
    :
else
    echo "  outlive: FAIL the detached daemon was not flagged at its exit"
    exit 1
fi

echo
echo "== 3. the benign corpus: zero questions, zero agent tags"
cd "$REPO/research/bypass"
for mode in write-only all-opens off; do
    ./benign.sh "$mode"
done

echo
echo "gate: all measurements ran. Numbers: results/corpus.txt, results above."
