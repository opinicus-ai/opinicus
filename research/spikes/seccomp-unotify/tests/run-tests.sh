#!/usr/bin/env bash
# The whole test set of the seccomp user notification spike.
#
# Every test runs a real program and checks a real result. No test needs root,
# a network or a database. Everything happens in the work directory of the
# spike, and the set can run again at any time.
#
# Usage: tests/run-tests.sh
set -uo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SPIKE_DIR"

WORK="$SPIKE_DIR/work/tests"
SUP="$SPIKE_DIR/bin/afw-unotify"
PASS=0
FAIL=0

pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s -- %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }
head1() { printf '\n== %s ==\n' "$1"; }

rm -rf "$WORK"
mkdir -p "$WORK"
make --no-print-directory all >/dev/null || exit 2

# ---------------------------------------------------------------------------
head1 "0. what this kernel gives to an unprivileged user"
# ---------------------------------------------------------------------------
"$SPIKE_DIR/bin/probe-listener" >"$WORK/probe.txt" 2>&1
sed 's/^/        /' "$WORK/probe.txt"
if grep -q "^new_listener_unprivileged = yes" "$WORK/probe.txt"; then
    pass "an unprivileged user can install a notification listener"
else
    fail "listener install" "see $WORK/probe.txt"
fi

# ---------------------------------------------------------------------------
head1 "1. can it refuse an action"
# ---------------------------------------------------------------------------
mkdir -p "$WORK/refuse"
printf 'ORIGINAL\n' >"$WORK/refuse/secret.txt"
printf 'ORIGINAL\n' >"$WORK/refuse/victim.txt"

"$SUP" --deny=secret.txt --log="$WORK/refuse/sup.log" -- \
    /bin/sh -c "echo OVERWRITTEN > $WORK/refuse/secret.txt" \
    >"$WORK/refuse/sh.out" 2>&1
if grep -q "Operation not permitted" "$WORK/refuse/sh.out"; then
    pass "a refused openat gives EPERM to the target"
else
    fail "openat EPERM" "$(cat "$WORK/refuse/sh.out")"
fi
if [ "$(cat "$WORK/refuse/secret.txt")" = "ORIGINAL" ]; then
    pass "the file content did not change"
else
    fail "file content" "the file was written"
fi

"$SUP" --deny=victim.txt -- /bin/rm -f "$WORK/refuse/victim.txt" \
    >"$WORK/refuse/rm.out" 2>&1
if [ -f "$WORK/refuse/victim.txt" ]; then
    pass "a refused unlinkat leaves the file on disk"
else
    fail "unlinkat" "the file is gone"
fi

# ---------------------------------------------------------------------------
head1 "2. can it read the arguments"
# ---------------------------------------------------------------------------
"$SUP" --log="$WORK/args.log" -- /bin/cat "$WORK/refuse/secret.txt" >/dev/null 2>&1
if grep -q "call=openat arg=$WORK/refuse/secret.txt" "$WORK/args.log"; then
    pass "the real path of an openat comes back from /proc/<pid>/mem"
else
    fail "path read" "no matching line in $WORK/args.log"
fi
if grep -q "call=openat arg=/etc/ld.so.cache" "$WORK/args.log"; then
    pass "the first openat after execve is also readable"
else
    fail "path after execve" "the /proc/<pid>/mem cache went stale"
fi

cat >"$WORK/conn.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("127.0.0.1", 9))
except OSError as e:
    print("errno", e.errno)
PY
"$SUP" --log="$WORK/conn.log" -- python3 "$WORK/conn.py" >/dev/null 2>&1
if grep -q "call=connect arg=inet 127.0.0.1:9" "$WORK/conn.log"; then
    pass "the sockaddr of a connect comes back as an address and a port"
else
    fail "sockaddr read" "no matching line in $WORK/conn.log"
fi
"$SUP" --deny="127.0.0.1:9" -- python3 "$WORK/conn.py" >"$WORK/conn.out" 2>&1
if grep -q "errno 1" "$WORK/conn.out"; then
    pass "a refused connect gives EPERM"
else
    fail "connect deny" "$(cat "$WORK/conn.out")"
fi

# ---------------------------------------------------------------------------
head1 "3. how reliable is the argument read"
# ---------------------------------------------------------------------------
RACE="$WORK/race"
mkdir -p "$RACE"
printf 'AAAA\n' >"$RACE/f_a.txt"
printf 'BBBB\n' >"$RACE/f_b.txt"
ITERS="${TOCTOU_ITERS:-2000}"

# 3a. The control. One thread, so the buffer never changes.
"$SUP" --log="$RACE/ctl.log" -- "$SPIKE_DIR/bin/toctou-open" \
    --dir="$RACE" --out="$RACE/ctl.out" --iters="$ITERS" --no-writer >/dev/null 2>&1
python3 tests/compare-toctou.py "$RACE/ctl.log" "$RACE/ctl.out" >"$RACE/ctl.txt"
CTL_RATE="$(awk -F= '/^mismatch_rate=/ {print $2}' "$RACE/ctl.txt")"
note "one thread: mismatch_rate=${CTL_RATE}%  ($(awk -F= '/^judged=/ {print $2}' "$RACE/ctl.txt") opens)"
if [ "$CTL_RATE" = "0.0" ]; then
    pass "with a stable buffer the supervisor reads the right path every time"
else
    fail "control" "rate $CTL_RATE, it should be 0.0"
fi

# 3b. The measurement. Two threads share the buffer.
"$SUP" --log="$RACE/race.log" -- "$SPIKE_DIR/bin/toctou-open" \
    --dir="$RACE" --out="$RACE/race.out" --iters="$ITERS" >/dev/null 2>&1
python3 tests/compare-toctou.py "$RACE/race.log" "$RACE/race.out" >"$RACE/race.txt"
RACE_RATE="$(awk -F= '/^mismatch_rate=/ {print $2}' "$RACE/race.txt")"
RACE_BAD="$(awk -F= '/^mismatch=/ {print $2}' "$RACE/race.txt")"
RACE_ALL="$(awk -F= '/^judged=/ {print $2}' "$RACE/race.txt")"
note "two threads: mismatch=$RACE_BAD of $RACE_ALL -> mismatch_rate=${RACE_RATE}%"
if [ "$RACE_BAD" -gt 0 ]; then
    pass "the path that the supervisor read is often not the path that was opened"
else
    fail "race" "no mismatch was seen; the test did not work"
fi

# 3c. The same race with a rule that refuses f_b.txt.
"$SUP" --deny=f_b.txt --log="$RACE/deny.log" -- "$SPIKE_DIR/bin/toctou-open" \
    --dir="$RACE" --out="$RACE/deny.out" --iters="$ITERS" >/dev/null 2>&1
python3 tests/compare-toctou.py "$RACE/deny.log" "$RACE/deny.out" >"$RACE/deny.txt"
DENY_B="$(awk -F= '/^opened_b_total=/ {print $2}' "$RACE/deny.txt")"
DENY_RAN="$(awk -F= '/^denied_but_ran=/ {print $2}' "$RACE/deny.txt")"
DENY_N="$(awk -F= '/^denied=/ {print $2}' "$RACE/deny.txt")"
note "rule 'refuse f_b.txt': refused=$DENY_N, but f_b.txt was opened $DENY_B times of $ITERS"
if [ "$DENY_B" -gt 0 ]; then
    pass "the rule does not hold: the refused file was opened anyway"
else
    fail "policy race" "the forbidden file was never opened"
fi
if [ "$DENY_RAN" -eq 0 ]; then
    pass "a refusal itself is never bypassed: no denied call ran"
else
    fail "deny enforcement" "$DENY_RAN denied calls still ran"
fi

# 3d. The same race, but the supervisor opens the file itself.
"$SUP" --allow=emulate --log="$RACE/emu.log" -- "$SPIKE_DIR/bin/toctou-open" \
    --dir="$RACE" --out="$RACE/emu.out" --iters="$ITERS" >/dev/null 2>&1
python3 tests/compare-toctou.py "$RACE/emu.log" "$RACE/emu.out" >"$RACE/emu.txt"
EMU_RATE="$(awk -F= '/^mismatch_rate=/ {print $2}' "$RACE/emu.txt")"
EMU_ALL="$(awk -F= '/^judged=/ {print $2}' "$RACE/emu.txt")"
note "emulation: mismatch_rate=${EMU_RATE}% over $EMU_ALL opens, writer thread running"
if [ "$EMU_RATE" = "0.0" ] && [ "$EMU_ALL" -gt 0 ]; then
    pass "emulation removes the race: the read of the supervisor decides"
else
    fail "emulation" "rate $EMU_RATE over $EMU_ALL opens"
fi

# 3e. The same race on the program start boundary.
EXECD="$WORK/exec"
mkdir -p "$EXECD"
cp /bin/true "$EXECD/p_a"
cp /bin/false "$EXECD/p_b"
chmod +x "$EXECD/p_a" "$EXECD/p_b"
"$SUP" --filter=exec --deny=p_b --log="$EXECD/sup.log" -- \
    "$SPIKE_DIR/bin/toctou-execve" --dir="$EXECD" --out="$EXECD/out.txt" \
    --iters=400 >/dev/null 2>&1
EXEC_B="$(awk '$2 == "b"' "$EXECD/out.txt" | wc -l)"
EXEC_ALLOW="$(grep -c "^allow .* call=execve arg=$EXECD/p_a" "$EXECD/sup.log")"
note "rule 'refuse p_b': the supervisor allowed $EXEC_ALLOW execve calls that read p_a,"
note "and the kernel ran the refused program p_b $EXEC_B times of 400"
if [ "$EXEC_B" -gt 0 ]; then
    pass "SECCOMP_USER_NOTIF_FLAG_CONTINUE ran a program the rule refused"
else
    fail "execve race" "p_b never ran"
fi

# ---------------------------------------------------------------------------
head1 "5. SECCOMP_USER_NOTIF_FLAG_CONTINUE and what emulation costs"
# ---------------------------------------------------------------------------
# Emulation saves openat, and it cannot save execve. There is no way for a
# supervisor to start a program for another process, so an allowed execve
# has to use CONTINUE, and CONTINUE re-reads the argument.
"$SUP" --filter=exec --allow=emulate --deny=p_b --log="$EXECD/emu.log" -- \
    "$SPIKE_DIR/bin/toctou-execve" --dir="$EXECD" --out="$EXECD/emu.txt" \
    --iters=400 >/dev/null 2>&1
EXEC_EMU_B="$(awk '$2 == "b"' "$EXECD/emu.txt" | wc -l)"
note "with emulation switched on, the refused program still ran $EXEC_EMU_B times of 400"
if [ "$EXEC_EMU_B" -gt 0 ]; then
    pass "emulation cannot save execve; an allowed execve stays racy"
else
    fail "execve emulation" "the race disappeared, which was not expected"
fi

# The filter works from the instant of the install. The child passes the
# listener descriptor with sendmsg, so a trapped sendmsg deadlocks the setup.
( timeout 8 "$SUP" --filter=full --trap-sendmsg -- /bin/echo hi \
    >/dev/null 2>&1 ) 2>/dev/null
DEAD_RC=$?
if [ "$DEAD_RC" -eq 124 ]; then
    pass "a trapped sendmsg deadlocks the setup: the fd pass is itself a sendmsg"
else
    fail "sendmsg deadlock" "rc=$DEAD_RC, a hang was expected"
fi
if timeout 8 "$SUP" --filter=full -- /bin/echo hi >/dev/null 2>&1; then
    pass "the same command works when sendmsg is not trapped"
else
    fail "sendmsg control" "the control run failed"
fi

# ---------------------------------------------------------------------------
head1 "4. SECCOMP_IOCTL_NOTIF_ID_VALID"
# ---------------------------------------------------------------------------
IDV="$WORK/idvalid"
mkdir -p "$IDV"
printf 'x\n' >"$IDV/hold-me-0.txt"
"$SUP" --trigger=hold-me --delay-ms=3000 --log="$IDV/sup.log" -- \
    "$SPIKE_DIR/bin/slow-target" --dir="$IDV" --files=1 --alarm-ms=400 \
    >"$IDV/target.out" 2>&1
TARGET_RC=$?
if grep -q "^id-valid-before .*hold-me-0" "$IDV/sup.log"; then
    pass "ID_VALID says the request is alive while the target waits"
else
    fail "id valid before" "no line"
fi
if grep -q "^stale-after-wait .*hold-me-0" "$IDV/sup.log"; then
    pass "ID_VALID sees that the target died during the decision"
else
    fail "id valid after" "no stale line, target rc=$TARGET_RC"
fi
if grep -q "^send-failed .*errno=ENOENT" "$IDV/sup.log"; then
    pass "the answer to a dead request fails with ENOENT"
else
    fail "send failed" "no line"
fi
RACE_STALE="$(grep -c "^stale" "$RACE/race.log")"
note "in the ${RACE_RATE}% race above, ID_VALID reported a problem $RACE_STALE times"
if [ "$RACE_STALE" -eq 0 ]; then
    pass "ID_VALID says nothing about a changed argument"
else
    fail "id valid scope" "unexpected stale lines in the race run"
fi

# ---------------------------------------------------------------------------
head1 "6. descendant coverage"
# ---------------------------------------------------------------------------
DESC="$WORK/desc"
mkdir -p "$DESC"
printf 'DEEP\n' >"$DESC/deep.txt"
"$SUP" --log="$DESC/nest.log" -- /bin/sh -c \
    "echo x | /bin/sh -c 'cat $DESC/deep.txt; grep -q DEEP $DESC/deep.txt; ( cat $DESC/deep.txt >/dev/null )'" \
    >/dev/null 2>&1
PIDS="$(grep -oE '^allow pid=[0-9]+' "$DESC/nest.log" | awk '{print $2}' | sort -u | wc -l)"
note "one listener saw $PIDS different processes"
if [ "$PIDS" -ge 3 ]; then
    pass "one listener carries a whole process tree"
else
    fail "descendants" "only $PIDS processes"
fi
"$SUP" --deny=deep.txt -- /bin/sh -c \
    "echo x | /bin/sh -c 'cat $DESC/deep.txt'" >"$DESC/deny.out" 2>&1
if grep -q "Operation not permitted" "$DESC/deny.out"; then
    pass "a refusal reaches a grandchild after two execve calls"
else
    fail "grandchild deny" "$(cat "$DESC/deny.out")"
fi
rm -f "$DESC/made.txt"
"$SUP" --deny=made.txt -- /bin/sh -c "( : > $DESC/made.txt )" >/dev/null 2>&1
if [ ! -f "$DESC/made.txt" ]; then
    pass "the filter also covers a forked child that never calls execve"
else
    fail "fork coverage" "the file was made"
fi
"$SUP" -- "$SPIKE_DIR/bin/probe-listener" >"$DESC/nested.txt" 2>&1
if grep -q "^new_listener_unprivileged = Device or resource busy" "$DESC/nested.txt"; then
    pass "a child under the monitor cannot install its own listener (EBUSY)"
else
    fail "nested listener" "$(grep new_listener "$DESC/nested.txt")"
fi

# ---------------------------------------------------------------------------
head1 "7. the no_new_privs cost"
# ---------------------------------------------------------------------------
"$SPIKE_DIR/bin/show-creds" --fork >"$WORK/creds-plain.txt" 2>&1
"$SUP" -- "$SPIKE_DIR/bin/show-creds" --fork >"$WORK/creds-mon.txt" 2>&1
sed 's/^/        without monitor: /' "$WORK/creds-plain.txt"
sed 's/^/        under monitor  : /' "$WORK/creds-mon.txt"
if grep -q "^self .*no_new_privs=1" "$WORK/creds-mon.txt" &&
   grep -q "^child .*no_new_privs=1" "$WORK/creds-mon.txt"; then
    pass "no_new_privs is set and a fork keeps it"
else
    fail "no_new_privs" "not set in every process"
fi
if [ -u /usr/bin/pkexec ]; then
    timeout 10 /usr/bin/pkexec /bin/true </dev/null >"$WORK/pkexec-plain.txt" 2>&1
    timeout 10 "$SUP" -- /usr/bin/pkexec /bin/true </dev/null \
        >"$WORK/pkexec-mon.txt" 2>&1
    note "without monitor: $(head -1 "$WORK/pkexec-plain.txt")"
    note "under monitor  : $(head -1 "$WORK/pkexec-mon.txt")"
    if grep -q "must be setuid root" "$WORK/pkexec-mon.txt" &&
       ! grep -q "must be setuid root" "$WORK/pkexec-plain.txt"; then
        pass "a setuid program loses its privilege under the monitor"
    else
        fail "setuid" "the two runs did not differ"
    fi
else
    note "/usr/bin/pkexec is not setuid on this machine; the test is skipped"
fi

# ---------------------------------------------------------------------------
head1 "8. failure modes"
# ---------------------------------------------------------------------------
FAILD="$WORK/failure"
mkdir -p "$FAILD"
for i in 0 1 2 3 4; do printf 'x\n' >"$FAILD/hold-me-$i.txt"; done

"$SUP" --trigger=hold-me --delay-ms=200 -- "$SPIKE_DIR/bin/slow-target" \
    --dir="$FAILD" --files=5 >"$FAILD/slow.out" 2>&1
SLOW_MS="$(awk '/^open 0 /{for (i=1;i<=NF;i++) if ($i ~ /^elapsed_ms=/) {split($i,a,"="); print a[2]}}' "$FAILD/slow.out")"
note "a supervisor that thinks for 200 ms blocks the target for ${SLOW_MS} ms"
if [ "${SLOW_MS:-0}" -ge 190 ]; then
    pass "the wait of the target is exactly the wait of the supervisor"
else
    fail "slow supervisor" "elapsed ${SLOW_MS} ms"
fi

timeout 20 "$SUP" --trigger=hold-me --no-answer -- "$SPIKE_DIR/bin/slow-target" \
    --dir="$FAILD" --files=5 --alarm-ms=1000 >"$FAILD/hang.out" 2>&1
HANG_RC=$?
note "a supervisor that never answers: wrapper rc=$HANG_RC (142 = a signal ended the target)"
if [ "$HANG_RC" -eq 142 ]; then
    pass "a target that waits for ever can still be ended by a signal"
else
    fail "killable" "rc=$HANG_RC"
fi

# The subshell hides the job message that the shell prints when the
# supervisor dies from its own timer.
( timeout 30 "$SUP" --trigger=hold-me --no-answer --suicide-ms=800 -- \
    "$SPIKE_DIR/bin/slow-target" --dir="$FAILD" --files=3 \
    >"$FAILD/die.out" 2>&1 ) 2>/dev/null
if grep -q "errno=38" "$FAILD/die.out"; then
    pass "when the supervisor dies, a waiting call fails at once with ENOSYS"
    note "$(head -1 "$FAILD/die.out")"
else
    fail "supervisor death" "$(cat "$FAILD/die.out")"
fi

"$SUP" --trigger=hold-me --delay-ms=1500 --log="$FAILD/sig.log" -- \
    "$SPIKE_DIR/bin/slow-target" --dir="$FAILD" --files=1 --alarm-ms=400 \
    --alarm-restart >"$FAILD/sig.out" 2>&1
SIG_N="$(grep -c '^allow .*hold-me-0' "$FAILD/sig.log")"
note "one open, one signal during the wait: the supervisor saw $SIG_N notifications"
if [ "$SIG_N" -ge 2 ]; then
    pass "a signal during the wait makes the kernel ask a second time"
else
    fail "signal restart" "only $SIG_N notification"
fi

# ---------------------------------------------------------------------------
printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
printf '  the numbers of question 3 are in %s\n' "$RACE"
[ "$FAIL" -eq 0 ]
