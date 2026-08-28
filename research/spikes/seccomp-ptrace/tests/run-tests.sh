#!/usr/bin/env bash
# Every claim of FINDINGS.md comes from one of these tests.
#
# Usage: ./tests/run-tests.sh [name-fragment]
#
# The script needs no root. It never touches a real database and never opens
# a connection to a real remote host: the only address that it uses is the
# loopback address of this machine.
set -uo pipefail

SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HYBRID="$SPIKE_DIR/build/afw-hybrid"
NNP="$SPIKE_DIR/build/nnp-probe"
VICTIM="$SPIKE_DIR/build/victim"
WORK="$SPIKE_DIR/work/tests"
FILTER="${1:-}"

PASSED=0
FAILED=0
CURRENT=""

start_test() {
    CURRENT="$1"
    rm -rf "$WORK"
    mkdir -p "$WORK"
}

check() {
    local label="$1"
    shift
    if "$@"; then
        printf '  ok    %s\n' "$label"
        PASSED=$((PASSED + 1))
    else
        printf '  FAIL  %s\n' "$label"
        FAILED=$((FAILED + 1))
    fi
}

check_true() {
    local label="$1"
    local value="$2"
    if [ "$value" = "1" ] || [ "$value" = "true" ]; then
        printf '  ok    %s\n' "$label"
        PASSED=$((PASSED + 1))
    else
        printf '  FAIL  %s (value %s)\n' "$label" "$value"
        FAILED=$((FAILED + 1))
    fi
}

check_equal() {
    local label="$1"
    local want="$2"
    local got="$3"
    if [ "$want" = "$got" ]; then
        printf '  ok    %s\n' "$label"
        PASSED=$((PASSED + 1))
    else
        printf '  FAIL  %s (want %s, got %s)\n' "$label" "$want" "$got"
        FAILED=$((FAILED + 1))
    fi
}

wants() {
    case "$1" in
        *"$FILTER"*) return 0 ;;
        *) return 1 ;;
    esac
}

if [ ! -x "$HYBRID" ]; then
    printf 'run-tests.sh: build the spike first with make\n' >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# 1. The filter is inherited by a child and it survives an execve.
# ---------------------------------------------------------------------------
if wants filter_survives_fork_and_exec; then
    printf '\nfilter_survives_fork_and_exec\n'
    start_test filter_survives_fork_and_exec
    echo "content of the sample" >"$WORK/sample.txt"
    "$HYBRID" --config c --log "$WORK/log" -- \
        /bin/sh -c "/bin/sh -c '/bin/cat $WORK/sample.txt'; /bin/true" >"$WORK/out" 2>&1
    root_pid="$(sed -n 's/^start pid=\([0-9]*\).*/\1/p' "$WORK/log" | head -1)"
    child_pid="$(sed -n 's/^fork pid=[0-9]* child=\([0-9]*\).*/\1/p' "$WORK/log" | head -1)"
    pids="$(sed -n 's/^seccomp pid=\([0-9]*\) .*/\1/p' "$WORK/log" | sort -u | wc -l)"
    execs="$(grep -c '^exec ' "$WORK/log")"

    check "the target still produced its output" grep -q "content of the sample" "$WORK/out"
    check "a fork was reported" test -n "$child_pid"
    check "the forked child is not the root" test "$child_pid" != "$root_pid"
    check "the filter reported calls of more than one process" test "$pids" -ge 2
    check "the child process reached a seccomp stop" \
        grep -q "^seccomp pid=$child_pid " "$WORK/log"
    check "a program three levels deep opened the file" \
        grep -q "^seccomp pid=$child_pid group=open_read call=openat.*$WORK/sample.txt" "$WORK/log"
    check "the exec events of af-monitor are still there" test "$execs" -ge 3
    check "an exit event is still reported" grep -q '^exit pid=' "$WORK/log"
fi

# ---------------------------------------------------------------------------
# 2. A refused system call never runs.
# ---------------------------------------------------------------------------
if wants a_refused_unlinkat_leaves_the_file; then
    printf '\na_refused_unlinkat_leaves_the_file\n'
    start_test a_refused_unlinkat_leaves_the_file
    echo "do not delete me" >"$WORK/target.txt"
    "$HYBRID" --config d --block unlinkat --log "$WORK/log" -- \
        /bin/rm -f "$WORK/target.txt" >"$WORK/out" 2>&1
    rm_status=$?

    check "the supervisor saw the delete" grep -q 'group=delete call=unlinkat' "$WORK/log"
    check "the supervisor refused the call" grep -q '^refused .*call=unlinkat' "$WORK/log"
    check "the file is still on disk" test -f "$WORK/target.txt"
    check "the content is unchanged" grep -q "do not delete me" "$WORK/target.txt"
    check "rm reported a failure" test "$rm_status" -ne 0
fi

# ---------------------------------------------------------------------------
# 3. The supervisor can decide on the path, which the kernel filter cannot.
# ---------------------------------------------------------------------------
if wants the_supervisor_can_refuse_by_path; then
    printf '\nthe_supervisor_can_refuse_by_path\n'
    start_test the_supervisor_can_refuse_by_path
    echo keep >"$WORK/keep-me.txt"
    echo drop >"$WORK/drop-me.txt"
    "$HYBRID" --config d --block unlinkat --block-path keep-me --log "$WORK/log" -- \
        /bin/rm -f "$WORK/keep-me.txt" "$WORK/drop-me.txt" >"$WORK/out" 2>&1

    check "the protected file is still there" test -f "$WORK/keep-me.txt"
    check "the other file is gone" test ! -f "$WORK/drop-me.txt"
    check "only one call was refused" \
        test "$(grep -c '^refused ' "$WORK/log")" -eq 1
fi

# ---------------------------------------------------------------------------
# 4. A filter that tests the flags hides every read from the supervisor.
# ---------------------------------------------------------------------------
if wants a_write_only_filter_hides_every_read; then
    printf '\na_write_only_filter_hides_every_read\n'
    start_test a_write_only_filter_hides_every_read
    mkdir -p "$WORK/files"
    for index in $(seq 1 40); do echo "line" >"$WORK/files/file-$index.txt"; done
    cat >"$WORK/job.sh" <<JOB
#!/bin/sh
cat $WORK/files/*.txt > $WORK/all.txt
JOB
    chmod +x "$WORK/job.sh"

    write_stats="$("$HYBRID" --config g --quiet --stats -- /bin/sh "$WORK/job.sh" 2>&1 >/dev/null |
        grep '^stats')"
    all_stats="$("$HYBRID" --config f --quiet --stats -- /bin/sh "$WORK/job.sh" 2>&1 >/dev/null |
        grep '^stats')"
    write_reads="$(printf '%s' "$write_stats" | grep -c 'open_read=' || true)"
    write_stops="$(printf '%s\n' "$write_stats" | sed -n 's/.*seccomp_stops=\([0-9]*\).*/\1/p')"
    all_stops="$(printf '%s\n' "$all_stats" | sed -n 's/.*seccomp_stops=\([0-9]*\).*/\1/p')"

    printf '  note  write filter: %s\n' "$write_stats"
    printf '  note  all-open filter: %s\n' "$all_stats"
    check_equal "the write filter never reported a read" "0" "$write_reads"
    check "the write filter woke the supervisor far less often" \
        test "$write_stops" -lt "$((all_stops / 4))"
    check "the write filter still saw the new file" \
        test "$(printf '%s\n' "$write_stats" | sed -n 's/.*open_write=\([0-9]*\).*/\1/p')" -ge 1
fi

# ---------------------------------------------------------------------------
# 5. A BPF filter cannot read the flags of openat2, because they sit behind
#    a pointer. The supervisor can, but only after it paid for a stop.
# ---------------------------------------------------------------------------
if wants the_kernel_cannot_test_the_flags_of_openat2; then
    printf '\nthe_kernel_cannot_test_the_flags_of_openat2\n'
    start_test the_kernel_cannot_test_the_flags_of_openat2
    stats="$("$HYBRID" --config g --log "$WORK/log" --stats -- \
        "$VICTIM" --openat2 "$WORK/made-by-openat2.txt" 2>&1 >/dev/null | grep '^stats')"

    check "the file was really made with openat2" test -f "$WORK/made-by-openat2.txt"
    check "a write-only filter still stops for every openat2" \
        grep -q 'call=openat2' "$WORK/log"
    check "the kernel could not label the call" grep -q 'group=open_how' "$WORK/log"
    check "the supervisor read the flags out of memory" \
        grep -q 'how_flags=0x41' "$WORK/log"
fi

# ---------------------------------------------------------------------------
# 6. seccomp needs PR_SET_NO_NEW_PRIVS for a process with no capability.
# ---------------------------------------------------------------------------
if wants seccomp_needs_no_new_privs; then
    printf '\nseccomp_needs_no_new_privs\n'
    start_test seccomp_needs_no_new_privs
    "$NNP" --check >"$WORK/out" 2>"$WORK/err"

    printf '  note  %s\n' "$(tr '\n' ' ' <"$WORK/err")"
    check "the kernel refuses a filter without no_new_privs" \
        grep -q 'without_nnp_accepted=0' "$WORK/out"
    check "the kernel accepts a filter with no_new_privs" \
        grep -q 'with_nnp_accepted=1' "$WORK/out"
    check "the refusal is EACCES" grep -q 'errno=13' "$WORK/err"
fi

# ---------------------------------------------------------------------------
# 7. no_new_privs removes the privilege of a setuid program. So does ptrace,
#    which af-monitor already uses, so the filter costs nothing extra here.
# ---------------------------------------------------------------------------
if wants ptrace_alone_already_removes_setuid; then
    printf '\nptrace_alone_already_removes_setuid\n'
    start_test ptrace_alone_already_removes_setuid
    user="$(id -un)"
    if [ ! -u /usr/bin/passwd ]; then
        printf '  skip  /usr/bin/passwd is not setuid on this machine\n'
    else
        plain="$(passwd -S "$user" 2>/dev/null | wc -w)"
        with_nnp="$("$NNP" --with-nnp -- passwd -S "$user" 2>/dev/null | wc -w)"
        under_ptrace="$("$HYBRID" --config x --quiet -- passwd -S "$user" 2>/dev/null | wc -w)"
        under_hybrid="$("$HYBRID" --config d --quiet -- passwd -S "$user" 2>/dev/null | wc -w)"

        printf '  note  fields: plain=%s nnp=%s ptrace=%s hybrid=%s\n' \
            "$plain" "$with_nnp" "$under_ptrace" "$under_hybrid"
        check "a setuid program reads the shadow file when nothing watches" \
            test "$plain" -gt 3
        check "no_new_privs takes the privilege away" test "$with_nnp" -lt "$plain"
        check "ptrace alone already takes the same privilege away" \
            test "$under_ptrace" -lt "$plain"
        check "the hybrid is no worse than plain ptrace" \
            test "$under_hybrid" -eq "$under_ptrace"
        check "the exec event reports the lowered user" \
            test "$("$HYBRID" --config x -- passwd -S "$user" 2>&1 >/dev/null |
                grep -c 'euid=1000')" -ge 1
    fi
fi

# ---------------------------------------------------------------------------
# 8. A filter that traces execve breaks the first execve when the tracer has
#    not set PTRACE_O_TRACESECCOMP yet. This is why the spike uses a second
#    stage, and why af-monitor must keep execve out of the filter.
# ---------------------------------------------------------------------------
if wants a_filter_without_a_tracer_breaks_execve; then
    printf '\na_filter_without_a_tracer_breaks_execve\n'
    start_test a_filter_without_a_tracer_breaks_execve
    echo hello >"$WORK/sample.txt"

    "$HYBRID" --direct --config a -- /bin/cat "$WORK/sample.txt" >"$WORK/out" 2>"$WORK/err"
    direct_status=$?
    "$HYBRID" --config a --log "$WORK/log2" -- /bin/cat "$WORK/sample.txt" \
        >"$WORK/out2" 2>&1
    stage2_status=$?

    check_equal "the direct install breaks the exec" "127" "$direct_status"
    check "the kernel skipped the call with ENOSYS" \
        grep -q 'Function not implemented' "$WORK/err"
    check_equal "the second stage repairs it" "0" "$stage2_status"
    check "the target ran" grep -q hello "$WORK/out2"
fi

# ---------------------------------------------------------------------------
# 9. The migration filter of af-monitor keeps execve out, so the child can
#    install it in the same place where af-monitor calls PTRACE_TRACEME.
# ---------------------------------------------------------------------------
if wants the_filter_installs_where_af_monitor_calls_traceme; then
    printf '\nthe_filter_installs_where_af_monitor_calls_traceme\n'
    start_test the_filter_installs_where_af_monitor_calls_traceme
    echo hello >"$WORK/sample.txt"
    "$HYBRID" --direct --config f --log "$WORK/log" -- \
        /bin/sh -c "/bin/cat $WORK/sample.txt" >"$WORK/out" 2>&1
    status=$?

    check_equal "the target ran with no second stage" "0" "$status"
    check "the output is correct" grep -q hello "$WORK/out"
    check "the filter still reported the open" \
        grep -q "call=openat.*$WORK/sample.txt" "$WORK/log"
    check "the exec event still comes from ptrace" grep -q '^exec pid=' "$WORK/log"
fi

# ---------------------------------------------------------------------------
# 10. PTRACE_O_EXITKILL still protects the machine when the supervisor dies
#     while a target waits at a seccomp stop.
# ---------------------------------------------------------------------------
if wants exitkill_stops_the_target_when_the_supervisor_dies; then
    printf '\nexitkill_stops_the_target_when_the_supervisor_dies\n'
    start_test exitkill_stops_the_target_when_the_supervisor_dies
    # The victim needs six seconds for its sixty tries. The supervisor
    # leaves after twenty-eight stops, which is about one second in.
    "$HYBRID" --config f --direct --log "$WORK/log" --die-after 28 -- \
        /bin/sh -c "$VICTIM /etc/hostname 60 100 >$WORK/victim.out; touch $WORK/marker" \
        >"$WORK/out" 2>&1
    supervisor_status=$?
    root_pid="$(sed -n 's/^start pid=\([0-9]*\).*/\1/p' "$WORK/log" | head -1)"
    first_count="$(wc -l <"$WORK/victim.out" 2>/dev/null || echo 0)"
    sleep 3
    second_count="$(wc -l <"$WORK/victim.out" 2>/dev/null || echo 0)"
    alive=0
    for pid in $(sed -n 's/^.*pid=\([0-9]*\).*/\1/p' "$WORK/log" | sort -u); do
        [ -d "/proc/$pid" ] && alive=$((alive + 1))
    done

    printf '  note  the victim wrote %s lines of 60, and %s three seconds later\n' \
        "$first_count" "$second_count"
    check_equal "the supervisor left on purpose" "70" "$supervisor_status"
    check "the target had really started its work" test "$first_count" -gt 0
    check "the target stopped at the same moment as the supervisor" \
        test "$first_count" -eq "$second_count"
    check "the target never finished" test "$second_count" -lt 60
    check "the last step of the target never ran" test ! -f "$WORK/marker"
    check "the root process is gone" test ! -d "/proc/$root_pid"
    check_equal "no process of the tree is left" "0" "$alive"
fi

# ---------------------------------------------------------------------------
# 11. The filter lives in the target, so it survives a detach. The gap costs
#     the target every traced call, because a call with no tracer is skipped
#     with ENOSYS.
# ---------------------------------------------------------------------------
if wants the_filter_survives_a_detach_and_a_restart; then
    printf '\nthe_filter_survives_a_detach_and_a_restart\n'
    start_test the_filter_survives_a_detach_and_a_restart
    "$HYBRID" --config f --direct --log "$WORK/log" --detach-after 6 --reattach-ms 400 -- \
        "$VICTIM" /etc/hostname 40 50 >"$WORK/victim.out" 2>&1
    status=$?
    ok_count="$(grep -c 'result=ok' "$WORK/victim.out" || true)"
    enosys_count="$(grep -c 'result=enosys' "$WORK/victim.out" || true)"
    last_enosys="$(grep -n 'result=enosys' "$WORK/victim.out" | tail -1 | cut -d: -f1)"
    last_ok="$(grep -n 'result=ok' "$WORK/victim.out" | tail -1 | cut -d: -f1)"
    stops_after="$(grep -c '^seccomp ' "$WORK/log" || true)"

    printf '  note  ok=%s enosys=%s\n' "$ok_count" "$enosys_count"
    check_equal "the target still ended well" "0" "$status"
    check "the supervisor detached" grep -q '^detach ' "$WORK/log"
    check "the supervisor came back" grep -q '^reattach ' "$WORK/log"
    check "calls worked before the detach" test "$ok_count" -gt 0
    check "every traced call failed while no tracer was there" test "$enosys_count" -gt 0
    check "the filter was still active after the restart" test "$last_ok" -gt "$last_enosys"
    check "the supervisor sees stops again" test "$stops_after" -gt 6
fi

# ---------------------------------------------------------------------------
# 12. A connect is visible with its address and port.
# ---------------------------------------------------------------------------
if wants the_supervisor_sees_a_connect; then
    printf '\nthe_supervisor_sees_a_connect\n'
    start_test the_supervisor_sees_a_connect
    # Only the loopback address of this machine, and a port that nothing
    # answers. No real remote host is ever contacted.
    "$HYBRID" --config d --log "$WORK/log" -- \
        /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' >"$WORK/out" 2>&1

    check "the connect was reported" grep -q 'group=connect call=connect' "$WORK/log"
    check "the address and the port are readable" \
        grep -q 'peer=127.0.0.1:9' "$WORK/log"
fi

# ---------------------------------------------------------------------------
# 13. The supervisor is transparent for a program that it allows.
# ---------------------------------------------------------------------------
if wants the_supervisor_keeps_the_result_of_the_target; then
    printf '\nthe_supervisor_keeps_the_result_of_the_target\n'
    start_test the_supervisor_keeps_the_result_of_the_target
    "$HYBRID" --config d --quiet -- /bin/sh -c 'exit 42' >"$WORK/out" 2>&1
    code=$?
    output="$("$HYBRID" --config d --quiet -- /bin/echo "the text of the target" 2>/dev/null)"

    check_equal "the exit code passes through" "42" "$code"
    check_equal "the output passes through" "the text of the target" "$output"
fi

# ---------------------------------------------------------------------------
# 14. A rule on the path of a call is not safe against a second thread.
# ---------------------------------------------------------------------------
if wants a_second_thread_defeats_a_path_rule; then
    printf '\na_second_thread_defeats_a_path_rule\n'
    start_test a_second_thread_defeats_a_path_rule
    # The target has two threads. One thread calls unlinkat. The other
    # thread changes the path in the shared buffer all the time. The
    # supervisor reads the path at the stop; the kernel reads it again when
    # the call runs. The two reads can give two different paths.
    printf 'decoy\n' >"$WORK/race-aaa.txt"
    printf 'protected\n' >"$WORK/race-bbb.txt"
    "$HYBRID" --config f --direct --quiet --block unlinkat \
        --block-path race-bbb -- \
        "$VICTIM" --race "$WORK/race-aaa.txt" "$WORK/race-bbb.txt" 200000 \
        >"$WORK/race-out" 2>/dev/null
    tries="$(sed -n 's/^race tries=\([0-9]*\).*/\1/p' "$WORK/race-out")"

    check "the protected file is gone, so the rule on the path lost the race" \
        test ! -e "$WORK/race-bbb.txt"
    printf '  note  the race needed %s tries\n' "${tries:-?}"

    # The same block, but with no rule on the path. The supervisor now
    # decides from the number of the call alone. The kernel cannot change
    # that value after the stop, so this block holds.
    printf 'decoy\n' >"$WORK/race-aaa.txt"
    printf 'protected\n' >"$WORK/race-bbb.txt"
    "$HYBRID" --config f --direct --quiet --stats --block unlinkat -- \
        "$VICTIM" --race "$WORK/race-aaa.txt" "$WORK/race-bbb.txt" 2000 \
        >"$WORK/race-out2" 2>&1
    deleted="$(sed -n 's/^race .*deleted=\([0-9]*\).*/\1/p' "$WORK/race-out2")"

    check_equal "a rule on the number of the call deletes nothing" "0" "$deleted"
    check "the protected file is still there" test -e "$WORK/race-bbb.txt"
    check "the decoy file is still there" test -e "$WORK/race-aaa.txt"
fi

printf '\npassed %d, failed %d\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
