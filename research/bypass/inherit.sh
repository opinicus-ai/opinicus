#!/usr/bin/env bash
# The inherited-descriptor gate of [af-12]: the launcher vector must be
# closed by launch hygiene, and the in-tree and SCM_RIGHTS vectors must be
# measured honestly and named.
#
# Rows (review P0-7, experiment EXP-T3):
#
#   launch    a hostile launcher pre-opens a writable file, a connected
#             socket, a memfd and a pidfd, none close-on-exec, then execs
#             the firewall itself keeping them open. The session root is
#             the payload, which counts /proc/self/fd and writes through
#             every inherited descriptor.
#   intree    a traced process opens and connects itself (both events
#             fire), then forks a child that writes through the inherited
#             descriptors without opening or connecting anything.
#   scm       a traced parent passes a live connected socket to a forked
#             child with SCM_RIGHTS; the child only uses it.
#
# PASS requires: every baseline effect works (the measurement is not
# broken); every builtin launch cell is closed — the payload sees exactly
# the three stdio descriptors and every write answers EBADF; the prefix
# binary (pre-hygiene build, optional) is only recorded. The intree and
# scm cells are the honest gaps: their verdict records what the trace
# covers and what it cannot.
#
# Usage: inherit.sh           (writes results/inherit.md)
#        FW_PREFIX=/path inherit.sh   to include the pre-hygiene binary
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
FW_PREFIX="${FW_PREFIX:-/tmp/agent-firewall-prefix}"
BIN="$DIR/bin"
OUT="$DIR/results/inherit"
PORT=45777
MODES="write-only all-opens off"

rm -rf "$OUT"
mkdir -p "$OUT"

"$DIR/techniques/build.sh" >/dev/null
if [ ! -x "$FW" ]; then
    echo "missing $FW; run cargo build --release" >&2
    exit 1
fi

# The same listener the matrix uses: one accept loop, one log line per
# received message.
LISTEN_LOG="$OUT/listen.log"
LISTENER_PID=""
start_listener() {
    rm -f "$LISTEN_LOG"
    python3 -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        data = c.recv(4096)
        open(sys.argv[1], 'a').write(data.decode(errors='replace'))
    finally:
        c.close()
" "$LISTEN_LOG" &
    LISTENER_PID=$!
    for _ in $(seq 50); do
        if python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    echo "listener did not come up" >&2
    return 1
}
stop_listener() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap stop_listener EXIT

# One answer per question, from the trace ($1) and the effects. $2 = the
# python expression, evaluated per event line as e.
trace_scan() {
    python3 - "$1" "$2" <<'PY'
import json, sys
n = 0
try:
    lines = open(sys.argv[1]).read().splitlines()
except FileNotFoundError:
    lines = []
for line in lines:
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    if eval(sys.argv[2]):  # noqa: S307 - a fixed expression of this script
        n += 1
print(n)
PY
}

has_token() {
    [ -f "$1" ] && grep -q "$2" "$1"
}

# Runs one cell. $1 = row label, $2 = the firewall under test (none for a
# baseline, the binary path otherwise), $3 = mode, $4 = direct|wrapped. The
# launch rows run the firewall inside the wrapper's own argv, so they pass
# direct; the wrapped rows get the firewall prefixed here. The rest = the
# command the row runs.
run_cell() {
    local label="$1" fw="$2" mode="$3" style="$4"
    shift 4
    local scratch="$OUT/$label"
    mkdir -p "$scratch"
    local victim="$scratch/victim.txt"
    local trace="$scratch/trace.jsonl"
    rm -f "$victim" "$LISTEN_LOG"

    start_listener
    set +e
    if [ "$style" = direct ]; then
        (cd "$scratch" && timeout 15 "$@" >out.txt 2>&1)
    else
        (cd "$scratch" && timeout 15 "$fw" run --retention all --approve deny \
            --syscall-filter "$mode" --trace "$trace" -- "$@" >out.txt 2>&1)
    fi
    local fw_exit=$?
    set -e
    stop_listener

    # The effects, always from the filesystem and the listener log.
    local file_ok=0 sock_ok=0
    if [[ "$label" == scm-* ]]; then
        if has_token "$LISTEN_LOG" "inherit-scm"; then sock_ok=1; fi
    else
        if has_token "$victim" "inherit-fd"; then file_ok=1; fi
        if has_token "$LISTEN_LOG" "inherit-fd"; then sock_ok=1; fi
    fi

    # What the trace covered. The child's use of a descriptor it never
    # opened has no event kind at all, so the witnesses name the parent's
    # open and connect only.
    local connects=0 opens=0 forks=0
    connects=$(trace_scan "$trace" "e.get('type')=='network_connect'")
    opens=$(trace_scan "$trace" "e.get('type')=='file_open' and e.get('write') and 'victim' in str(e.get('path',''))")
    forks=$(trace_scan "$trace" "e.get('type')=='process_fork'")

    # The payload's own report, for the launch rows.
    local fds="?"
    if [ -f "$scratch/out.txt" ]; then
        fds=$( { grep -o 'fds=[0-9-]*' "$scratch/out.txt" || true; } | tail -1 | cut -d= -f2)
    fi
    case "$fds" in
        ''|*[!0-9-]*) fds=0 ;;
    esac

    local verdict
    if [[ "$label" == launch-* ]]; then
        if [ "$fw" = none ]; then
            if [ "$file_ok" = 1 ] && [ "$sock_ok" = 1 ] && [ "${fds:-0}" -gt 3 ]; then
                verdict="works (fds=$fds, writes landed)"
            else
                verdict="BROKEN (fds=$fds file=$file_ok sock=$sock_ok)"
            fi
        elif [ "$fw" = "$FW_PREFIX" ]; then
            verdict="recorded (fds=$fds file=$file_ok sock=$sock_ok)"
        elif [ "$fds" = 3 ] && [ "$file_ok" = 0 ] && [ "$sock_ok" = 0 ]; then
            verdict="closed (fds=3, every write EBADF)"
        else
            verdict="LEAKED (fds=$fds file=$file_ok sock=$sock_ok)"
        fi
    elif [[ "$label" == intree-* ]]; then
        if [ "$fw" = none ]; then
            if [ "$file_ok" = 1 ] && [ "$sock_ok" = 1 ]; then
                verdict="works"
            else
                verdict="BROKEN (file=$file_ok sock=$sock_ok)"
            fi
        elif [ "$file_ok" = 1 ] && [ "$sock_ok" = 1 ]; then
            verdict="open gap: child use silent (parent open=$opens connect=$connects fork=$forks)"
        else
            verdict="action-failed (file=$file_ok sock=$sock_ok)"
        fi
    else
        if [ "$fw" = none ]; then
            if [ "$sock_ok" = 1 ]; then
                verdict="works"
            else
                verdict="BROKEN (sock=$sock_ok)"
            fi
        elif [ "$sock_ok" = 1 ]; then
            verdict="open gap: child use silent (parent connect=$connects fork=$forks)"
        else
            verdict="action-failed (sock=$sock_ok)"
        fi
    fi

    printf '| %s | %s | %s | %s |\n' "$label" "${fw##*/}" "$fw_exit" "$verdict"
}

{
    printf '| row | firewall | exit | verdict |\n'
    printf '| --- | --- | --- | --- |\n'

    # The launch vector, baseline first: the wrapper execs the payload
    # directly, so the inherited descriptors must all work.
    run_cell launch-baseline none none direct \
        "$BIN/inherit-fd" launch "$OUT/launch-baseline/victim.txt" "$PORT" \
        "$BIN/inherit-fd" payload
    # The launch vector against the firewall, before and after the launch
    # hygiene. The wrapper execs the firewall itself with the descriptors
    # held open; the payload is the session root.
    if [ -x "$FW_PREFIX" ]; then
        for mode in $MODES; do
            run_cell "launch-prefix-$mode" "$FW_PREFIX" "$mode" direct \
                "$BIN/inherit-fd" launch "$OUT/launch-prefix-$mode/victim.txt" "$PORT" \
                "$FW_PREFIX" run --retention all --approve deny \
                --syscall-filter "$mode" --trace "$OUT/launch-prefix-$mode/trace.jsonl" \
                -- "$BIN/inherit-fd" payload
        done
    else
        printf '| launch-prefix (skipped) | — | — | no %s |\n' "$FW_PREFIX"
    fi
    for mode in $MODES; do
        run_cell "launch-builtin-$mode" "$FW" "$mode" direct \
            "$BIN/inherit-fd" launch "$OUT/launch-builtin-$mode/victim.txt" "$PORT" \
            "$FW" run --retention all --approve deny \
            --syscall-filter "$mode" --trace "$OUT/launch-builtin-$mode/trace.jsonl" \
            -- "$BIN/inherit-fd" payload
    done

    # The in-tree vector: open and connect inside the session, then use
    # through fork inheritance.
    run_cell intree-baseline none none direct \
        "$BIN/inherit-fd" intree "$OUT/intree-baseline/victim.txt" "$PORT"
    for mode in $MODES; do
        run_cell "intree-builtin-$mode" "$FW" "$mode" wrapped \
            "$BIN/inherit-fd" intree "$OUT/intree-builtin-$mode/victim.txt" "$PORT"
    done

    # The SCM_RIGHTS vector: one connect inside the session, the live
    # descriptor passed mid-run, the child only uses it.
    run_cell scm-baseline none none direct \
        "$BIN/inherit-scm" "$PORT"
    for mode in $MODES; do
        run_cell "scm-builtin-$mode" "$FW" "$mode" wrapped \
            "$BIN/inherit-scm" "$PORT"
    done
} | tee "$DIR/results/inherit.md"

echo
BROKEN=$(grep -c 'BROKEN' "$DIR/results/inherit.md" || true)
LEAKED=$(grep -c 'LEAKED' "$DIR/results/inherit.md" || true)
echo "inherit gate: $LEAKED leaked launch cells, $BROKEN broken measurements"
[ "$BROKEN" -eq 0 ] && [ "$LEAKED" -eq 0 ]
