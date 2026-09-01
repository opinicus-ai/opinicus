#!/usr/bin/env bash
# hostile-extkill — an external SIGKILL of the monitor. Ticket [af-12],
# review P1-6 / EXP-T2.
#
# The kernel filter holds a kill of the monitor only for processes of the
# session (the filter lives in their own address space); a process outside
# the tree carries no filter at all, and yama gates no signal. The
# technique finds the monitor the way the C techniques do — the payload
# named by the marker, then its TracerPid — and sends SIGKILL from outside
# the tree. The finding is what answers: the signal succeeds at every yama
# level, the monitor dies, and PTRACE_O_EXITKILL takes the tree with it —
# fail-closed, with no tamper event anywhere.
#
#   hostile-extkill <marker-path>
set -euo pipefail
marker="$1"
tracer=0
payload=0
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = "$$" ] && continue
    cmdline=$(tr '\0' ' ' <"$d/cmdline" 2>/dev/null || true)
    case "$cmdline" in
    *"$marker"*)
        # The command line of the monitor names the marker too (it carries
        # the whole payload command after `--`), and nothing traces the
        # monitor: the payload is the match that a tracer holds.
        this_tracer=$(awk '/^TracerPid:/ {print $2}' "$d/status" 2>/dev/null || echo 0)
        if [ "$this_tracer" -ne 0 ]; then
            payload=$pid
            tracer=$this_tracer
            break
        fi
        ;;
    esac
done
if [ "$payload" -eq 0 ]; then
    echo "ACTION hostile-extkill no-payload rc=-1"
    exit 0
fi
if [ "$tracer" -eq 0 ]; then
    echo "ACTION hostile-extkill no-tracer payload=$payload"
    exit 0
fi
echo "STEP hostile-extkill target monitor=$tracer payload=$payload"
rc=0
kill -KILL "$tracer" 2>/dev/null || rc=$?
echo "ACTION hostile-extkill kill signal=9 monitor=$tracer rc=$rc"
exit 0
