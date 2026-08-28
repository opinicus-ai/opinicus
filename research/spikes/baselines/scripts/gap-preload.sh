#!/usr/bin/env bash
# gap-preload.sh - the structural gaps of LD_PRELOAD interposition.
#
# The mechanism can only see a call that the dynamic linker binds. Three
# ordinary cases break that condition:
#
#   1. a statically linked program, which never runs the dynamic linker;
#   2. a program that reaches the kernel with syscall() instead of the libc
#      wrapper;
#   3. a child that inherits an environment without the variable.
#
# Every case ends by writing a marker file. The marker proves that the action
# happened. The log then shows whether the monitor saw the action.
#
# The check looks only at action lines: openat, unlink and connect. An execve
# line can hold the marker path as an argument, and that is not a record of
# the action.
#
# The script itself does not run under LD_PRELOAD. Only the case command
# does, so the log holds no noise from grep, sed or cat.
set -euo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$SPIKE_DIR/results/gap-preload.txt"
WORK="$SPIKE_DIR/scratch/preload"
LOG="$WORK/monitor.log"
LIB="$SPIKE_DIR/bin/libafwpreload.so"

rm -rf "$WORK"
mkdir -p "$WORK" "$SPIKE_DIR/results"

# Runs one case under the interposer. The command always starts from a shell
# that has the library loaded, so the execve of the program is itself a
# chance for the monitor to see something.
run_case() {
    env LD_PRELOAD="$LIB" AFW_PRELOAD_LOG="$LOG" /bin/sh -c "$1" \
        >/dev/null 2>&1 || true
}

report_case() {
    local name="$1"
    local marker="$2"
    local marker_state="MISSING"
    local action_state="NO RECORD"
    local exec_state="no"

    [ -e "$marker" ] && marker_state="written"
    if grep -E "^(openat|unlink|connect) " "$LOG" 2>/dev/null |
        grep -Fq -- "$marker"; then
        action_state="recorded"
    fi
    if grep -E "^execve " "$LOG" 2>/dev/null | grep -Fq -- "$marker"; then
        exec_state="yes"
    fi
    printf '%-30s marker=%-8s action_in_log=%-10s exec_in_log=%s\n' \
        "$name" "$marker_state" "$action_state" "$exec_state"
}

{
    printf '# the structural gaps of LD_PRELOAD\n'
    printf '# date: %s\n' "$(date -Is)"
    printf '# library: %s\n' "$LIB"
    printf '# wrapped functions: execve, openat, unlink, connect\n\n'

    : >"$LOG"

    # --------------------------------------------------------------
    # The control. Everything goes through the dynamic libc.
    # --------------------------------------------------------------
    printf '## control, a dynamic program that uses the libc wrappers\n'
    run_case "'$SPIKE_DIR/bin/marker_libc' '$WORK/marker-control.txt'"
    report_case "dynamic libc, openat+unlink" "$WORK/marker-control.txt"

    rm -f "$WORK/port" "$WORK/listen-result"
    python3 "$SPIKE_DIR/workloads/one_shot_listener.py" "$WORK/port" \
        "$WORK/listen-result" 10 >/dev/null 2>&1 &
    listener=$!
    for _ in $(seq 1 100); do
        [ -s "$WORK/port" ] && break
        sleep 0.05
    done
    if [ -s "$WORK/port" ]; then
        port="$(cat "$WORK/port")"
        run_case "'$SPIKE_DIR/bin/marker_libc' \
            '$WORK/marker-connect.txt' '$port'"
        wait "$listener" 2>/dev/null || true
        if grep -Fq "port=$port" "$LOG"; then
            printf '%-30s marker=%-8s action_in_log=%s\n' \
                "dynamic libc, connect" "written" "recorded (port $port)"
        else
            printf '%-30s marker=%-8s action_in_log=%s\n' \
                "dynamic libc, connect" "written" "NO RECORD"
        fi
        printf 'the listener reports: %s\n' \
            "$(head -1 "$WORK/listen-result" 2>/dev/null)"
    else
        kill "$listener" 2>/dev/null || true
        printf 'the listener did not start, the connect case was skipped\n'
    fi

    # --------------------------------------------------------------
    # Gap 1.
    # --------------------------------------------------------------
    printf '\n## gap 1, a statically linked program\n'
    printf 'own static program: %s\n' \
        "$(file -b "$SPIKE_DIR/bin/marker_static" | cut -d, -f1-4)"
    printf 'INTERP segments in its ELF header: %s\n' \
        "$(readelf -l "$SPIKE_DIR/bin/marker_static" | grep -c INTERP ||
            true)"
    run_case "'$SPIKE_DIR/bin/marker_static' '$WORK/marker-static.txt'"
    report_case "own static program" "$WORK/marker-static.txt"

    if [ -x "$SPIKE_DIR/bin/gomarker" ]; then
        printf 'static Go program: %s\n' \
            "$(file -b "$SPIKE_DIR/bin/gomarker" | cut -d, -f1-4)"
        run_case "'$SPIKE_DIR/bin/gomarker' '$WORK/marker-go.txt'"
        report_case "static Go program" "$WORK/marker-go.txt"
    else
        printf 'the static Go program was not built, so that case is '
        printf 'skipped\n'
    fi

    # --------------------------------------------------------------
    # Gap 2.
    # --------------------------------------------------------------
    printf '\n## gap 2, a program that calls the kernel directly\n'
    run_case "'$SPIKE_DIR/bin/marker_rawsyscall' '$WORK/marker-raw.txt'"
    report_case "raw syscall(SYS_openat)" "$WORK/marker-raw.txt"

    # --------------------------------------------------------------
    # Gap 3.
    # --------------------------------------------------------------
    printf '\n## gap 3, a child with the variable changed\n'
    run_case "env -u LD_PRELOAD '$SPIKE_DIR/bin/marker_libc' \
        '$WORK/marker-envstrip.txt'"
    report_case "env -u LD_PRELOAD" "$WORK/marker-envstrip.txt"

    run_case "LD_PRELOAD= '$SPIKE_DIR/bin/marker_libc' \
        '$WORK/marker-envempty.txt'"
    report_case "LD_PRELOAD= before the command" "$WORK/marker-envempty.txt"

    run_case "unset LD_PRELOAD; '$SPIKE_DIR/bin/marker_libc' \
        '$WORK/marker-unset.txt'"
    report_case "unset LD_PRELOAD in a shell" "$WORK/marker-unset.txt"

    # --------------------------------------------------------------
    # How likely is a normal coding agent to meet each case?
    # --------------------------------------------------------------
    printf '\n## how common these cases are on this machine\n'
    printf 'statically linked programs in /usr/bin: %s of %s ELF files\n' \
        "$(file /usr/bin/* 2>/dev/null | grep -c 'statically linked' ||
            true)" \
        "$(file /usr/bin/* 2>/dev/null | grep -c 'ELF ' || true)"
    printf 'the names of those programs:\n'
    file /usr/bin/* 2>/dev/null | grep 'statically linked' |
        cut -d: -f1 | sed 's/^/  /' || true
    printf 'a static-pie program of the base system:\n'
    printf '  %s: %s\n' /usr/sbin/ldconfig \
        "$(file -b /usr/sbin/ldconfig | cut -d, -f1-4)"

    # --------------------------------------------------------------
    # The record.
    # --------------------------------------------------------------
    printf '\n## every action line that the monitor recorded\n'
    grep -E "^(openat|unlink|connect) " "$LOG" | sed 's/^/  /' ||
        printf '  (none)\n'

    printf '\n## every execve line that the monitor recorded\n'
    grep -E '^execve ' "$LOG" | sed 's/^/  /' || printf '  (none)\n'
} | tee "$OUT"

printf '\nwritten to %s\n' "$OUT"
