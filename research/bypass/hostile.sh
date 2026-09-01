#!/usr/bin/env bash
# The hostile same-UID gate of [af-12]: five techniques attack the monitor
# from OUTSIDE the monitored tree, under the yama ptrace_scope levels this
# machine can carry.
#
# The question of ticket [af-12] (review P1-6 / EXP-T2): what does the
# kernel, the firewall, or nothing at all hold against a hostile process
# that shares the monitor's uid and stands outside the tree? The kernel
# filter holds kill/tkill/tgkill only inside the session (the filter lives
# in the traced processes), yama gates the ptrace-class routes, and the
# signal checks pass for any same-uid sender.
#
#   hostile-ptrace   PTRACE_ATTACH + PTRACE_POKETEXT on the monitor
#   hostile-vmem     process_vm_writev into the monitor
#   hostile-procmem  a write through /proc/<monitor>/mem
#   hostile-pidfd    pidfd_open + pidfd_getfd + pidfd_send_signal
#   hostile-extkill  kill -KILL from a process outside the tree
#
# Each technique finds the monitor the way an attacker would — /proc scan
# for the payload named by the marker, then its TracerPid — and prints the
# errno of every step. PASS here is not "the monitor survived": it is that
# every cell reads exactly one of
#
#   denied-by-kernel        the route failed with EPERM/EACCES (yama)
#   succeeded-unsensed      the route worked, the monitor lived, no event
#   succeeded-fail-closed   the monitor died, PTRACE_O_EXITKILL took the
#                           tree, the trace kept its durable lines and no
#                           tamper event names the kill
#   no-session              yama 2/3 refused the launch itself: PTRACE_
#                           TRACEME answers EPERM, the monitor never
#                           started, and there is nothing to attack
#
# and that everything but the first row is recorded as an accepted gap in
# docs/DECISIONS.md, not as protection. The negative side of this gate is
# research/bypass/benign.sh: nothing here adds a rule or a question. (A
# machine pinned at scope 3 cannot run that corpus — the monitor cannot
# launch, the no-session rows apply to the corpus too.)
#
# The yama sysctl is machine-global, and scope 3 is a ONE-WAY switch: once
# set, the kernel refuses to lower it — measured here, `sudo sysctl -w`
# answers "Invalid argument" even for root — until the machine reboots.
# The harness therefore measures 0, 1 and 2 always (restoring the original
# value after each level) and measures 3 only when the caller opts in with
# SCOPE3=1, accepting that the machine stays at 3 until reboot. On a
# machine already at 3 the harness measures that one level and says so.
# Everything except the sysctl runs as a normal user; passwordless sudo is
# required for `sysctl -w`.
#
# Usage: hostile.sh          (writes results/hostile.md and results/hostile.json)
#        SCOPE3=1 hostile.sh (also measures scope 3, one-way, last)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
BIN="$DIR/bin"
YAMA=/proc/sys/kernel/yama/ptrace_scope
OUT="$DIR/results/hostile"
TABLE="$DIR/results/hostile.md"

[ -x "$FW" ] || { echo "hostile.sh: no release build at $FW (cargo build --release)" >&2; exit 1; }
sudo -n true 2>/dev/null || { echo "hostile.sh: needs passwordless sudo for the yama sysctl" >&2; exit 1; }

"$DIR/techniques/build.sh" >/dev/null

ORIG_YAMA="$(cat "$YAMA")"
restore_yama() {
    sudo sysctl -w "kernel.yama.ptrace_scope=$ORIG_YAMA" >/dev/null
}
trap restore_yama EXIT

# The levels this run measures: every level the one-way rule allows. A
# machine already at 3 can measure only 3; a lower machine measures 0, 1,
# 2, and 3 behind the explicit opt-in because 3 does not go back.
LEVELS=()
case "$ORIG_YAMA" in
0 | 1 | 2)
    LEVELS=(0 1 2)
    if [ "${SCOPE3:-0}" = 1 ]; then
        LEVELS+=(3)
    else
        echo "note: SCOPE3 is not 1; skipping scope 3 (one-way until reboot; opt in with SCOPE3=1)"
    fi
    ;;
3)
    echo "note: this machine already sits at yama ptrace_scope 3 (one-way); measuring that level only"
    LEVELS=(3)
    ;;
esac

rm -rf "$OUT"
mkdir -p "$OUT"

# How long the payload of one cell lives, in one-second sleeps. The
# attack lands within the first two seconds; a cell whose monitor survives
# ends when the payload ends. The payload is a loop and not one `sleep`, so
# its command line keeps naming the marker for its whole life (a shell
# replaces itself with its last command, and the scan would lose it).
PAYLOAD_SECONDS=8

# Runs one cell: a monitored session in the background, the attack from
# this shell (outside the tree), then the bookkeeping. $1 = technique,
# $2 = yama scope, rest = the attack command.
run_cell() {
    local name="$1" yama="$2"; shift 2
    local scratch="$OUT/$name.y$yama"
    mkdir -p "$scratch"
    local marker="$scratch/af12-ready"
    local trace="$scratch/trace.jsonl"
    echo "yama_scope=$yama" >"$scratch/attack.out"

    # The session: a payload whose command line names the marker, alive
    # long enough for the attack to find it from outside.
    (cd "$scratch" && exec timeout 45 "$FW" run \
        --retention all --approve deny --trace "$trace" \
        -- sh -c "echo \$\$ > '$marker'; for i in \$(seq $PAYLOAD_SECONDS); do sleep 1; done" \
        </dev/null >"$scratch/fw.out" 2>"$scratch/fw.err") &
    local fw_job=$!

    # Wait for the payload to live (its pid is in the marker), then attack.
    # Under yama 2/3 the launch itself fails and no payload ever appears:
    # the cell then measures the refusal, not an attack.
    local _
    for _ in $(seq 1 150); do
        [ -s "$marker" ] && break
        kill -0 "$fw_job" 2>/dev/null || break
        sleep 0.1
    done
    if [ ! -s "$marker" ]; then
        echo "PAYLOAD-NEVER-STARTED" >>"$scratch/attack.out"
        "$@" >>"$scratch/attack.out" 2>&1 || true
        set +e
        wait "$fw_job"
        local dead_exit=$?
        set -e
        echo "fw_exit=$dead_exit" >>"$scratch/attack.out"
        return
    fi

    set +e
    "$@" >>"$scratch/attack.out" 2>&1
    echo "attack_rc=$?" >>"$scratch/attack.out"

    # What survived the attack itself, judged while the session may still
    # run: this is the honest moment for "did the monitor live through it".
    # After the wait below, a monitor that survived has exited normally and
    # says dead without meaning it.
    local monitor
    monitor=$(sed -n 's/^STEP .*monitor=\([0-9]*\).*/\1/p' "$scratch/attack.out" | head -1)
    [ -n "$monitor" ] && kill -0 "$monitor" 2>/dev/null \
        && echo "monitor_after_attack=alive" >>"$scratch/attack.out" \
        || echo "monitor_after_attack=dead" >>"$scratch/attack.out"

    wait "$fw_job"
    local fw_exit=$?
    set -e
    local payload
    payload=$(cat "$marker")
    kill -0 "$payload" 2>/dev/null \
        && echo "payload=alive" >>"$scratch/attack.out" \
        || echo "payload=dead" >>"$scratch/attack.out"
    echo "fw_exit=$fw_exit" >>"$scratch/attack.out"
}

for yama in "${LEVELS[@]}"; do
    echo "yama ptrace_scope: $ORIG_YAMA -> $yama"
    sudo sysctl -w "kernel.yama.ptrace_scope=$yama" >/dev/null
    run_cell hostile-ptrace  "$yama" "$BIN/hostile-ptrace"  "$OUT/hostile-ptrace.y$yama/af12-ready"
    run_cell hostile-vmem    "$yama" "$BIN/hostile-vmem"    "$OUT/hostile-vmem.y$yama/af12-ready"
    run_cell hostile-procmem "$yama" "$BIN/hostile-procmem" "$OUT/hostile-procmem.y$yama/af12-ready"
    run_cell hostile-pidfd   "$yama" "$BIN/hostile-pidfd"   "$OUT/hostile-pidfd.y$yama/af12-ready"
    run_cell hostile-extkill "$yama" "$BIN/hostile-extkill.sh" "$OUT/hostile-extkill.y$yama/af12-ready"
    # Back to the original after every level: a walk that ends on a raised
    # level cannot come home (scope 3 is one-way, scope 2 and 1 are not).
    if [ "$yama" != 3 ]; then
        restore_yama
    fi
done

if [ "${LEVELS[-1]}" = 3 ]; then
    echo "warning: yama ptrace_scope sits at 3, and the kernel refuses to lower it"
    echo "warning: (measured: sudo sysctl -w answers Invalid argument even as root)"
    echo "warning: the machine stays at 3 until it reboots; the original value was $ORIG_YAMA"
    trap - EXIT
else
    restore_yama
    trap - EXIT
fi

# The matrix, from the raw cells only: the attack's own errno answers, the
# trace, and the liveness of monitor and tree after the fact.
python3 - "$OUT" "$TABLE" "$ORIG_YAMA" <<'PY'
import json, os, re, sys

out, table, orig = sys.argv[1], sys.argv[2], sys.argv[3]
techniques = ["hostile-ptrace", "hostile-vmem", "hostile-procmem", "hostile-pidfd", "hostile-extkill"]
verbs = ("attach", "readv", "writev", "open", "pread", "pwrite", "poketext",
         "pidfd_open", "pidfd_getfd", "pidfd_send_signal", "kill", "no-payload", "no-tracer")

def facts(path):
    summary = {}
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        return {"no-cell": True}
    for line in lines:
        m = re.match(r"ACTION (\S+) (\w+)", line)
        if m and m.group(2) in verbs:
            e = re.search(r"errno=(-?\d+)", line)
            summary[m.group(2)] = e.group(1) if e else "?"
        if "=" in line and not line.startswith(("ACTION", "STEP")):
            k, v = line.split("=", 1)
            summary[k] = v
    summary["payload_never_started"] = "PAYLOAD-NEVER-STARTED" in lines
    return summary

def trace_facts(path):
    kinds, tamper = [], 0
    try:
        for line in open(path):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            kinds.append(e.get("type"))
            if e.get("type") == "tamper":
                tamper += 1
    except FileNotFoundError:
        pass
    return {"lines": len(kinds), "session_end": kinds.count("session_end"),
            "tamper": tamper}

def verdict(a, t):
    if a.get("payload_never_started"):
        return "no-session"
    died = a.get("monitor_after_attack") == "dead"
    tree_alive = a.get("payload") == "alive"
    denied = any(a.get(v) in ("1", "13") for v in ("attach", "readv", "writev", "open", "pidfd_getfd"))
    if died and not tree_alive:
        return "succeeded-fail-closed"
    if died and tree_alive:
        return "succeeded-tree-survived"
    if denied:
        return "denied-by-kernel"
    return "succeeded-unsensed"

def errno_word(n):
    return {"1": "EPERM", "13": "EACCES", "0": "ok"}.get(n, f"errno {n}")

rows = []
for tech in techniques:
    for yama in range(4):
        cell = os.path.join(out, f"{tech}.y{yama}")
        if not os.path.isdir(cell):
            continue
        a = facts(os.path.join(cell, "attack.out"))
        t = trace_facts(os.path.join(cell, "trace.jsonl"))
        steps = " ".join(f"{v}={errno_word(a[v])}" for v in verbs if v in a)
        if a.get("payload_never_started"):
            steps = "no session: PTRACE_TRACEME refused, the monitor never started"
        rows.append({"technique": tech, "yama": yama, "attack": steps,
                     "monitor": a.get("monitor_after_attack", "-"),
                     "tree": a.get("payload", "-"),
                     "fw_exit": a.get("fw_exit", "-"),
                     "verdict": verdict(a, t), "trace": t})

with open(table, "w") as fh:
    fh.write("| technique | yama | attack errno | monitor | tree | fw exit | trace lines | session_end | tamper | verdict |\n")
    fh.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
    for r in rows:
        fh.write(f"| {r['technique']} | {r['yama']} | {r['attack']} | {r['monitor']} | "
                 f"{r['tree']} | {r['fw_exit']} | {r['trace']['lines']} | "
                 f"{r['trace']['session_end']} | {r['trace']['tamper']} | {r['verdict']} |\n")

with open(os.path.join(out, "hostile.json"), "w") as fh:
    json.dump({"yama_original": orig, "cells": rows}, fh, indent=1)

print(open(table).read())
PY

echo "yama ptrace_scope now: $(cat "$YAMA") (original: $ORIG_YAMA)"
