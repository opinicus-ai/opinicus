#!/usr/bin/env bash
#
# End-to-end test of the Agent Firewall.
#
# A person or a continuous-integration job can run this test. The test builds
# the workspace, runs three sessions and checks ten assertions. The test
# writes a summary and returns a non-zero code when one assertion fails.
# The summary goes to standard error, so a caller that pipes standard output
# away (`| tee`, `| head`) still sees the verdict; such a caller reads the
# exit code with PIPESTATUS, because the code of a pipeline is the code of
# its last command.
#
# The test touches no real database. The fake psql client in demo/bin only
# prints. The git steps use a throwaway repository. Every temporary file
# stays in one directory, and a trap removes that directory.
#
# Usage:
#   tests/e2e.sh [--no-build]
#
# Options:
#   --no-build   Does not run cargo. The binary must already exist.
#
# Environment:
#   AFW_BIN         Path of an existing agent-firewall binary.
#   AFW_KEEP_WORK   Set this to 1 to keep the working directory. Use this to
#                   study a failure.
#   NO_COLOR        Switches the colours off.
#
# The core assertion of the whole project is B2: after a denied session, the
# marker file of the fake client holds no DROP DATABASE line. The dangerous
# program never ran.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
DEMO_DIR="$REPO_ROOT/demo"

# shellcheck source=demo/lib/scenario.sh
. "$DEMO_DIR/lib/scenario.sh"

usage() {
    printf 'usage: %s [--no-build]\n' "$0"
}

want_build="yes"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-build)
            want_build="no"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown argument "%s"\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

afw_setup_colors

# ---------------------------------------------------------------------------
# Assertion helpers.
# ---------------------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
FAILED_NAMES=()

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '%s  ok  %s %s\n' "$AFW_GREEN" "$AFW_RESET" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_NAMES+=("$1")
    printf '%s FAIL %s %s\n' "$AFW_RED" "$AFW_RESET" "$1"
    printf '       %s\n' "$2"
}

# Compares two strings.
assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$name"
    else
        fail "$name" "expected [$expected], got [$actual]"
    fi
}

# Compares an exit code.
assert_exit() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" -eq "$actual" ]; then
        pass "$name"
    else
        fail "$name" "expected exit code $expected, got $actual"
    fi
}

# Checks that an exit code is not zero.
assert_exit_nonzero() {
    local name="$1" actual="$2"
    if [ "$actual" -ne 0 ]; then
        pass "$name"
    else
        fail "$name" "expected a non-zero exit code, got 0"
    fi
}

# Checks that a text holds a fixed string.
#
# The grep reads the haystack from a temporary file of the shell, not from a
# pipe: `printf | grep -q` answers the match by leaving the pipe early, and
# under load a writer that still has more bytes than the pipe holds can die of
# SIGPIPE. With `pipefail` on, that turned a found match into a failed
# assertion (measured: five false failures in 3000 probes under load, writer
# status 141, grep status 0). The here-string form has no pipe and no such
# failure mode.
assert_contains() {
    local name="$1" haystack="$2" needle="$3"
    if grep -q -F -- "$needle" <<<"$haystack"; then
        pass "$name"
    else
        fail "$name" "the text holds no [$needle]"
        head -n 20 <<<"$haystack" | sed -e 's/^/       | /'
    fi
}

# Checks that a text does not hold a fixed string.
assert_not_contains() {
    local name="$1" haystack="$2" needle="$3"
    if grep -q -F -- "$needle" <<<"$haystack"; then
        fail "$name" "the text holds [$needle], but it must not"
        grep -F -- "$needle" <<<"$haystack" | head -n 5 | sed -e 's/^/       | /' || true
    else
        pass "$name"
    fi
}

# Checks that a text matches an extended regular expression.
assert_matches() {
    local name="$1" haystack="$2" pattern="$3"
    if grep -q -E -- "$pattern" <<<"$haystack"; then
        pass "$name"
    else
        fail "$name" "the text matches no [$pattern]"
        head -n 20 <<<"$haystack" | sed -e 's/^/       | /'
    fi
}

# Runs a command. The output of both streams goes to RUN_OUTPUT. The exit
# code goes to RUN_STATUS. The helper never stops the test.
RUN_OUTPUT=""
RUN_STATUS=0
run_capture() {
    RUN_OUTPUT=""
    RUN_STATUS=0
    RUN_OUTPUT="$("$@" 2>&1)" || RUN_STATUS=$?
    return 0
}

# Prints the content of a file, or nothing when the file does not exist.
file_text() {
    if [ -f "$1" ]; then
        cat -- "$1"
    fi
}

# Prints "yes" when a tree text shows psql below migrate.sh.
#
# The check reads the first line that names migrate.sh and the first line
# after it that names psql. The psql line must stand deeper. The position of
# the first letter or digit of a line gives the depth, so the check works for
# spaces and for line-drawing characters.
tree_shows_psql_below_migrate() {
    printf '%s\n' "$1" | awk '
        function depth(line,   position) {
            position = match(line, /[A-Za-z0-9]/)
            return position - 1
        }
        migrate == 0 && /migrate\.sh/ { migrate = NR; migrate_depth = depth($0); next }
        migrate > 0 && psql == 0 && /psql/ { psql = NR; psql_depth = depth($0) }
        END {
            if (migrate > 0 && psql > migrate && psql_depth > migrate_depth) {
                print "yes"
            } else {
                print "no"
            }
        }
    '
}

# ---------------------------------------------------------------------------
# Preparation.
# ---------------------------------------------------------------------------

BINARY="$(afw_find_binary "$REPO_ROOT" "$want_build")"

WORK_DIR="$REPO_ROOT/tmp/e2e-$$"
# The trap below calls this function.
# shellcheck disable=SC2329
cleanup() {
    if [ "${AFW_KEEP_WORK:-0}" = "1" ]; then
        printf 'the working directory stays: %s\n' "$WORK_DIR" >&2
        return
    fi
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p -- "$WORK_DIR"
afw_make_workspace "$WORK_DIR" "$DEMO_DIR"
PROJECT_DIR="$WORK_DIR/project"

export PATH="$DEMO_DIR/bin:$PATH"
export AFW_DEMO_REPO="$PROJECT_DIR"

printf '%sAgent Firewall end-to-end test%s\n' "$AFW_BOLD" "$AFW_RESET"
printf 'binary:    %s\n' "$BINARY"
printf 'workspace: %s\n' "$WORK_DIR"
printf '\n'

# ---------------------------------------------------------------------------
# A. A harmless session runs without a change.
# ---------------------------------------------------------------------------

printf '%sA — a harmless session%s\n' "$AFW_BOLD" "$AFW_RESET"

status_a=0
"$BINARY" run --approve deny --trace "$WORK_DIR/trace-a.jsonl" -- sh -c 'echo hello' \
    >"$WORK_DIR/a.stdout" 2>"$WORK_DIR/a.stderr" || status_a=$?

assert_exit "A1 the session ends with code 0" 0 "$status_a"
assert_eq "A2 the child writes hello on standard output" "hello" "$(file_text "$WORK_DIR/a.stdout")"

# ---------------------------------------------------------------------------
# B. The firewall stops the dangerous action.
# ---------------------------------------------------------------------------

printf '\n%sB — the dangerous session with --approve deny%s\n' "$AFW_BOLD" "$AFW_RESET"

MARKER_B="$WORK_DIR/marker-b.txt"
TRACE_B="$WORK_DIR/trace-b.jsonl"

status_b=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_B" AFW_DEMO_GIT=1 \
        "$BINARY" run --approve deny --trace "$TRACE_B" --print-tree -- bash ./agent-sim.sh
) >"$WORK_DIR/b.stdout" 2>"$WORK_DIR/b.stderr" || status_b=$?

marker_b_text="$(file_text "$MARKER_B")"

assert_exit "B1 the firewall stopped the session" 3 "$status_b"
assert_not_contains "B2 the marker file holds no DROP DATABASE line" "$marker_b_text" "DROP DATABASE"
assert_contains "B3 the harmless statements still ran" "$marker_b_text" "EXECUTED: SELECT 1"
assert_contains "B4 the firewall explained the decision" \
    "$(file_text "$WORK_DIR/b.stderr")" "database.destructive.drop-database"

# ---------------------------------------------------------------------------
# C. The user allows the dangerous action.
# ---------------------------------------------------------------------------

printf '\n%sC — the dangerous session with --approve allow%s\n' "$AFW_BOLD" "$AFW_RESET"

MARKER_C="$WORK_DIR/marker-c.txt"
TRACE_C="$WORK_DIR/trace-c.jsonl"

status_c=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_C" \
        "$BINARY" run --approve allow --trace "$TRACE_C" -- bash ./agent-sim.sh
) >"$WORK_DIR/c.stdout" 2>"$WORK_DIR/c.stderr" || status_c=$?

assert_exit "C1 the session ends with code 0" 0 "$status_c"
assert_contains "C2 the marker file holds the DROP DATABASE line" \
    "$(file_text "$MARKER_C")" "EXECUTED: DROP DATABASE customer_prod"

# ---------------------------------------------------------------------------
# D. The trace holds the policy decision.
# ---------------------------------------------------------------------------

printf '\n%sD — the trace of the denied session%s\n' "$AFW_BOLD" "$AFW_RESET"

decision_lines="$(grep -E '"type" *: *"policy_decision"' "$TRACE_B" 2>/dev/null |
    grep -F 'database.destructive.drop-database' || true)"

assert_contains "D1 the trace holds a policy_decision for the drop rule" \
    "$decision_lines" "database.destructive.drop-database"
assert_matches "D2 the decision of the rule is not allow" \
    "$decision_lines" '"decision" *: *"(approval_required|deny|terminate)"'

# ---------------------------------------------------------------------------
# E. The tree command shows the provenance chain.
# ---------------------------------------------------------------------------

printf '\n%sE — the process tree of the trace%s\n' "$AFW_BOLD" "$AFW_RESET"

run_capture "$BINARY" tree "$TRACE_B"
tree_text="$RUN_OUTPUT"

assert_exit "E1 the tree command ends with code 0" 0 "$RUN_STATUS"
assert_contains "E2 the tree holds psql" "$tree_text" "psql"
assert_eq "E3 psql stands below migrate.sh" "yes" "$(tree_shows_psql_below_migrate "$tree_text")"

# ---------------------------------------------------------------------------
# F. The replay finds the same rule again.
# ---------------------------------------------------------------------------

printf '\n%sF — the replay of the trace%s\n' "$AFW_BOLD" "$AFW_RESET"

run_capture "$BINARY" replay "$TRACE_B"

assert_contains "F1 the replay finds the same rule" \
    "$RUN_OUTPUT" "database.destructive.drop-database"

# ---------------------------------------------------------------------------
# G. The rules pass their own tests.
# ---------------------------------------------------------------------------

printf '\n%sG — the policy tests%s\n' "$AFW_BOLD" "$AFW_RESET"

run_capture "$BINARY" policy test
assert_exit "G1 policy test ends with code 0" 0 "$RUN_STATUS"

# ---------------------------------------------------------------------------
# H. The policy checker accepts good files and rejects bad files.
# ---------------------------------------------------------------------------

printf '\n%sH — the policy checker%s\n' "$AFW_BOLD" "$AFW_RESET"

run_capture "$BINARY" policy check "$REPO_ROOT/policies"
assert_exit "H1 policy check accepts the policies directory" 0 "$RUN_STATUS"

# This file is wrong in four ways: the rule has no identifier, the decision
# does not exist, the risk level does not exist, and the match block holds an
# unknown field. Every schema must reject it.
BAD_RULE="$WORK_DIR/bad-rule.yaml"
cat >"$BAD_RULE" <<'EOF'
version: 1
name: test.bad-rule
description: a deliberately wrong policy file for the end-to-end test
rules:
  - title: "a rule without an identifier"
    risk: "extremely-dangerous"
    decision: "obliterate"
    match:
      program: "psql"
      field_that_no_schema_knows: true
EOF

run_capture "$BINARY" policy check "$BAD_RULE"
assert_exit_nonzero "H2 policy check rejects a bad rule file" "$RUN_STATUS"

# ---------------------------------------------------------------------------
# I. The doctor reports the capabilities of the machine.
# ---------------------------------------------------------------------------

printf '\n%sI — the doctor%s\n' "$AFW_BOLD" "$AFW_RESET"

run_capture "$BINARY" doctor
assert_exit "I1 doctor ends with code 0" 0 "$RUN_STATUS"
assert_contains "I2 doctor reports exec_interception" "$RUN_OUTPUT" "exec_interception"

# ---------------------------------------------------------------------------
# J. Normal work produces no question.
# ---------------------------------------------------------------------------

printf '\n%sJ — normal work stays quiet%s\n' "$AFW_BOLD" "$AFW_RESET"

MARKER_J="$WORK_DIR/marker-j.txt"
TRACE_J="$WORK_DIR/trace-j.jsonl"

status_j=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_J" \
        "$BINARY" run --approve deny --trace "$TRACE_J" -- bash ./agent-sim.sh --safe-only
) >"$WORK_DIR/j.stdout" 2>"$WORK_DIR/j.stderr" || status_j=$?

assert_exit "J1 the harmless session ends with code 0" 0 "$status_j"
assert_eq "J2 the trace holds no approval question" \
    "0" "$(afw_trace_matches "$TRACE_J" '"type" *: *"approval_requested"')"
assert_eq "J3 the trace holds no strong decision" \
    "0" "$(afw_trace_matches "$TRACE_J" '"decision" *: *"(approval_required|deny|terminate)"')"

# ---------------------------------------------------------------------------
# K. The kernel floor: a credential read two shells deep fails with no
#    prompt, and the session explains why.
#
# The floor is the Landlock layer of research/spikes/landlock: the "always
# no" rule classes of the built-in pack, enacted in the kernel before the
# first program runs. The key path below is an invented name inside the real
# .ssh directory: the floor hides the whole directory, the denial happens
# whether or not the file exists, and no real credential is ever read.
# ---------------------------------------------------------------------------

printf '\n%sK — the kernel floor answers without asking%s\n' "$AFW_BOLD" "$AFW_RESET"

TRACE_K="$WORK_DIR/trace-k.jsonl"

status_k=0
"$BINARY" run --approve deny --syscall-filter all-opens --trace "$TRACE_K" \
    -- sh -c "sh -c \"cat ~/.ssh/id_afw_e2e_key\"" \
    >"$WORK_DIR/k.stdout" 2>"$WORK_DIR/k.stderr" || status_k=$?

assert_exit_nonzero "K1 the credential read two shells deep fails" "$status_k"
assert_eq "K2 the trace holds no approval question" \
    "0" "$(afw_trace_matches "$TRACE_K" '"type" *: *"approval_requested"')"
assert_contains "K3 the session names the rule the kernel enforced" \
    "$(file_text "$WORK_DIR/k.stderr")" "filesystem.credentials.read"
assert_contains "K4 the trace records the kernel denial" \
    "$(file_text "$TRACE_K")" "kernel_denied"
assert_contains "K5 the trace records the kernel floor" \
    "$(file_text "$TRACE_K")" "kernel_floor"

# The write side runs in the default mode: an open that asks to change a
# credential file is held by the kernel filter, matches the write rule, and
# the kernel answers it — no question, and the same explanation.
TRACE_KW="$WORK_DIR/trace-kw.jsonl"

status_kw=0
"$BINARY" run --approve deny --trace "$TRACE_KW" \
    -- sh -c "sh -c \"printf backdoor >> ~/.ssh/id_afw_e2e_key\"" \
    >"$WORK_DIR/kw.stdout" 2>"$WORK_DIR/kw.stderr" || status_kw=$?

assert_exit_nonzero "K6 the credential write two shells deep fails" "$status_kw"
assert_eq "K7 the write asks no question either" \
    "0" "$(afw_trace_matches "$TRACE_KW" '"type" *: *"approval_requested"')"
assert_contains "K8 the write names the write rule" \
    "$(file_text "$WORK_DIR/kw.stderr")" "filesystem.credentials.write"

# The same shape OUTSIDE the hidden prefixes: a .ssh under the work tree
# (equivalently under /tmp) is writable as far as the floor is concerned —
# the /tmp and work-tree grants cover it — so this write keeps its question.
# The pack denies it and explains it; that is the contract of
# docs/LANDLOCK-CONTRACT.md for credential shapes in writable trees.
TRACE_KT="$WORK_DIR/trace-kt.jsonl"

status_kt=0
(
    cd "$PROJECT_DIR"
    "$BINARY" run --approve deny --trace "$TRACE_KT" \
        -- sh -c "mkdir -p .ssh && printf backdoor > .ssh/id_afw_e2e_tmp"
) >"$WORK_DIR/kt.stdout" 2>"$WORK_DIR/kt.stderr" || status_kt=$?

assert_exit_nonzero "K9 a .ssh created in the work tree is not written silently" \
    "$status_kt"
assert_eq "K10 the write keeps its question (the floor does not cover it)" \
    "1" "$(afw_trace_matches "$TRACE_KT" '"type" *: *"approval_requested"')"
assert_contains "K11 the question names the credential write rule" \
    "$(file_text "$WORK_DIR/kt.stderr")" "filesystem.credentials.write"
if [ -e "$PROJECT_DIR/.ssh/id_afw_e2e_tmp" ]; then
    assert_eq "K12 the key file was never created" "absent" "present"
else
    assert_eq "K12 the key file was never created" "absent" "absent"
fi

# ---------------------------------------------------------------------------
# T. Tamper and quarantine: the seeded techniques of the bypass harness fire
#    every time, the ruling is one question, and the quarantine holds the
#    tree. The techniques are the sources of research/bypass/techniques,
#    compiled here so the test needs nothing but a C compiler.
#
#    The negative side of this section is the benign corpus of the harness
#    (research/bypass/benign.sh), which must produce zero quarantines in
#    all three filter modes.
# ---------------------------------------------------------------------------

printf '\n%sT — tamper sensing and the quarantine flow%s\n' "$AFW_BOLD" "$AFW_RESET"

TECH="$REPO_ROOT/research/bypass/techniques"
for src in kill-monitor escape-setsid respawn strip-preload sensor-blind; do
    cc -O2 -o "$WORK_DIR/$src" "$TECH/$src.c"
done
SENSOR="$REPO_ROOT/research/spikes/inprocess/libafsensor.so"
[ -f "$SENSOR" ] || { printf 'error: %s is missing; run research/spikes/inprocess/build.sh\n' "$SENSOR" >&2; exit 2; }

# T1–T4: a program that signals the monitor is held, judged and quarantined
# before the signal runs. The auto-deny of this harness refuses the call, so
# the monitor survives what was a blind spot of M1.
TRACE_T="$WORK_DIR/trace-t.jsonl"
status_t=0
"$BINARY" run --approve deny --retention all --trace "$TRACE_T" \
    -- "$WORK_DIR/kill-monitor" "$WORK_DIR/t-marker.txt" \
    >"$WORK_DIR/t.stdout" 2>"$WORK_DIR/t.stderr" || status_t=$?

assert_exit_nonzero "T1 the monitor-kill session is stopped by the ruling" "$status_t"
assert_eq "T2 the trace holds the held signal" \
    "1" "$(afw_trace_matches "$TRACE_T" '"type" *: *"signal_send"')"
assert_eq "T3 the tamper rule fired" \
    "1" "$(afw_trace_matches "$TRACE_T" '"type" *: *"policy_decision".*"rule_id" *: *"tamper.monitor.signal"')"
assert_eq "T4 the tree was quarantined exactly once" \
    "1" "$(afw_trace_matches "$TRACE_T" '"type" *: *"quarantine_started"')"
assert_eq "T5 one ruling, one answer" \
    "1" "$(afw_trace_matches "$TRACE_T" '"type" *: *"quarantine_resolved"')"
assert_contains "T6 the kill never ran" "$(file_text "$WORK_DIR/t.stdout")" "blocked"

# T7–T9: a descendant that leaves the session tree is a sensed fact and a
# report. It must not quarantine, because git maintenance makes the same
# shape on every commit of a normal session.
TRACE_TE="$WORK_DIR/trace-te.jsonl"
status_te=0
"$BINARY" run --approve deny --retention all --trace "$TRACE_TE" \
    -- "$WORK_DIR/escape-setsid" "$WORK_DIR/te-marker.txt" \
    >"$WORK_DIR/te.stdout" 2>"$WORK_DIR/te.stderr" || status_te=$?

assert_exit "T7 the detached session still runs to its end" 0 "$status_te"
assert_contains "T8 the detach fact fired" \
    "$(file_text "$TRACE_TE")" '"kind":"detached_descendant"'
assert_eq "T9 the detach reports and never asks" \
    "0" "$(afw_trace_matches "$TRACE_TE" '"type" *: *"quarantine_started"')"

# T10–T12: a program the firewall killed that comes back quarantines the
# tree. The respawn loop runs a command the built-in pack denies; every
# round after the first kill is the sensed fact.
TRACE_TR="$WORK_DIR/trace-tr.jsonl"
status_tr=0
"$BINARY" run --approve deny --retention all --trace "$TRACE_TR" \
    -- "$WORK_DIR/respawn" 3 \
    >"$WORK_DIR/tr.stdout" 2>"$WORK_DIR/tr.stderr" || status_tr=$?

assert_exit_nonzero "T10 the respawn loop is stopped by a ruling" "$status_tr"
assert_contains "T11 the killed program that came back fired" \
    "$(file_text "$TRACE_TR")" '"kind":"killed_subtree_returned"'
assert_contains "T12 the quarantine suspended the tree" \
    "$(file_text "$WORK_DIR/tr.stderr")" "the session tree is suspended"

# T13–T15: a child that inherits no copy of the sensor preload is sensed at
# the exec boundary and quarantined. Without the sensor in the environment
# the same session must stay quiet, which the T16 run proves.
TRACE_TS="$WORK_DIR/trace-ts.jsonl"
status_ts=0
LD_PRELOAD="$SENSOR" \
    AF_SENSOR_TRACE="$WORK_DIR/ts-sensor.jsonl" \
    AF_SENSOR_REG="$WORK_DIR/ts-sensor.reg" \
    AF_SENSOR_SESSION=afw-e2e-strip \
    "$BINARY" run --approve deny --retention all --trace "$TRACE_TS" \
    -- "$WORK_DIR/strip-preload" "$WORK_DIR/ts-marker.txt" \
    >"$WORK_DIR/ts.stdout" 2>"$WORK_DIR/ts.stderr" || status_ts=$?

assert_exit_nonzero "T13 the stripped-preload session is stopped by a ruling" "$status_ts"
assert_contains "T14 the preload fact fired" \
    "$(file_text "$TRACE_TS")" '"kind":"preload_stripped"'
assert_contains "T15 the session carries the sensor facts" \
    "$(file_text "$TRACE_TS")" "libafsensor.so"

TRACE_TN="$WORK_DIR/trace-tn.jsonl"
status_tn=0
"$BINARY" run --approve deny --retention all --trace "$TRACE_TN" \
    -- sh -c 'echo quiet' \
    >"$WORK_DIR/tn.stdout" 2>"$WORK_DIR/tn.stderr" || status_tn=$?
assert_exit "T16 a session without the sensor stays quiet" 0 "$status_tn"
assert_eq "T17 no tamper fact of any kind fired" \
    "0" "$(afw_trace_matches "$TRACE_TN" '"type" *: *"tamper"')"

# T18: the recorder writes the process events through, so the death of the
# monitor leaves the evidence instead of erasing it — the M1 finding. With
# no filter and no floor there is nothing to hold or refuse the kill, so the
# monitor dies with the tree, and the trace must still name the program.
TRACE_TD="$WORK_DIR/trace-td.jsonl"
status_td=0
"$BINARY" run --approve deny --retention all --syscall-filter off --landlock off \
    --trace "$TRACE_TD" \
    -- "$WORK_DIR/kill-monitor" "$WORK_DIR/td-marker.txt" \
    >"$WORK_DIR/td.stdout" 2>"$WORK_DIR/td.stderr" || status_td=$?
assert_contains "T18 a killed monitor leaves the evidence of what ran" \
    "$(file_text "$TRACE_TD")" "kill-monitor"

# ---------------------------------------------------------------------------
# C. Correlation: the expected view of the sensor against the observed view
#    of the monitor, on recorded pairs. A blinded sensor raises the
#    discrepancy and the rule fires; a session that stripped the preload
#    stays quiet for correlation, because M4 owns that fact live; the
#    emitted findings read back as a trace and replay with the rules.
# ---------------------------------------------------------------------------

printf '\n%sC — the correlation engine%s\n' "$AFW_BOLD" "$AFW_RESET"

# T19–T20: the blinded sensor. The technique closes the sensor's own
# descriptors mid-run, so its instance goes quiet while the process lives
# on — the correlation engine reads the two views afterwards and the rule
# fires on the recorded pair.
TRACE_CB="$WORK_DIR/trace-cb.jsonl"
status_cb=0
LD_PRELOAD="$SENSOR" \
    AF_SENSOR_TRACE="$WORK_DIR/cb-sensor.jsonl" \
    AF_SENSOR_REG="$WORK_DIR/cb-sensor.reg" \
    AF_SENSOR_SESSION=afw-e2e-blind \
    "$BINARY" run --approve deny --retention all --trace "$TRACE_CB" \
    -- "$WORK_DIR/sensor-blind" "$WORK_DIR/cb-marker.txt" \
    >"$WORK_DIR/cb.stdout" 2>"$WORK_DIR/cb.stderr" || status_cb=$?

assert_exit "T19 the blinded session runs to its end" 0 "$status_cb"
CORRELATE_CB="$("$BINARY" correlate "$TRACE_CB" \
    --sensor "$WORK_DIR/cb-sensor.jsonl" --reg "$WORK_DIR/cb-sensor.reg" \
    --emit "$WORK_DIR/cb-findings.jsonl")"
assert_contains "T20 the silent sensor raised its discrepancy and its rule" \
    "$CORRELATE_CB" "sensor_silent_subtree"
assert_contains "T20a the rule of the pack fired" \
    "$CORRELATE_CB" "correlation.sensor.silent-subtree"
"$BINARY" tree "$WORK_DIR/cb-findings.jsonl" >"$WORK_DIR/cb-tree.txt" 2>&1
assert_contains "T20b the emitted findings read back as a trace" \
    "$(file_text "$WORK_DIR/cb-findings.jsonl")" '"kind":"sensor_silent_subtree"'

# T21: the stripped preload belongs to the tamper pack, live; the
# correlation view must stay quiet about the same session, because the
# child's environment names no sensor to contradict.
CORRELATE_TS="$("$BINARY" correlate "$TRACE_TS" \
    --sensor "$WORK_DIR/ts-sensor.jsonl" --reg "$WORK_DIR/ts-sensor.reg")"
assert_not_contains "T21 the stripped-preload session stays quiet for correlation" \
    "$CORRELATE_TS" "spawn_seen_unreported"

# T22: the emitted findings replay with the current rules and the same
# discrepancy fires again — the trace is the shared contract.
REPLAY_CB="$("$BINARY" replay "$WORK_DIR/cb-findings.jsonl")"
assert_contains "T22 the discrepancy trace replays with the rules" \
    "$REPLAY_CB" "correlation.sensor.silent-subtree"

# ---------------------------------------------------------------------------
# U. io_uring: the ring road is held at the call boundary, reported by the
#    pack, and refused when the host chooses the deny. The technique of the
#    bypass harness (evade-15) performed an open with write intent through
#    one io_uring_enter and produced zero events in every filter mode; the
#    filter now holds io_uring_setup and io_uring_enter, the rule of the
#    tamper pack reports every call, and a local rule file that replaces
#    the rule with a deny closes the road completely — the shipped posture
#    of [af-12], decided on the measured numbers
#    (docs/DECISIONS.md, 2026-09-01): a normal node session makes the
#    calls on its own, so a default deny would fire on everyday work.
#    The negative side is the benign corpus (research/bypass/benign.sh)
#    and the in-file tests of policies/tamper.yaml.
# ---------------------------------------------------------------------------

printf '\n%sU — the io_uring ring is held, reported, and refusable%s\n' "$AFW_BOLD" "$AFW_RESET"

cc -O2 -o "$WORK_DIR/uring" "$REPO_ROOT/research/bypass/techniques/uring.c"

# U1–U5: the shipped posture. The calls are held and seen — the zero-events
# gap is closed as visibility — the rule reports, and no question stands,
# so the road itself stays open and the marker of the technique appears.
TRACE_U="$WORK_DIR/trace-u.jsonl"
status_u=0
"$BINARY" run --approve deny --retention all --trace "$TRACE_U" \
    -- "$WORK_DIR/uring" "$WORK_DIR/u-marker.txt" \
    >"$WORK_DIR/u.stdout" 2>"$WORK_DIR/u.stderr" || status_u=$?

assert_exit "U1 the reported ring session runs to its end" 0 "$status_u"
assert_eq "U2 the trace holds the held ring calls" \
    "2" "$(afw_trace_matches "$TRACE_U" '"type" *: *"io_uring"')"
assert_eq "U3 the io_uring rule fired as a report on every held call" \
    "2" "$(afw_trace_matches "$TRACE_U" '"type" *: *"policy_decision".*"rule_id" *: *"tamper.bypass.io-uring"')"
assert_eq "U4 the report asks nothing" \
    "0" "$(afw_trace_matches "$TRACE_U" '"decision" *: *"(approval_required|deny|terminate)"')"
[ -f "$WORK_DIR/u-marker.txt" ] && pass "U5 the road itself stays open under the shipped posture" || \
    fail "U5 the road itself stays open under the shipped posture"

# U6–U10: the host-requirement enforcement, from a local rule file that
# replaces the report with a deny. The filter already holds the calls, so
# the deny is complete: the ring never performs anything.
LOCAL_POLICY="$WORK_DIR/uring-deny.yaml"
cat >"$LOCAL_POLICY" <<'POLICY'
version: 1
name: local.uring-deny
description: The host-requirement enforcement of the io_uring decision — replace the report with a deny for the sessions that load this file.
rules:
  - id: tamper.bypass.io-uring
    title: io_uring use inside the session
    category: tamper
    risk: blocked
    decision: deny
    reason: This host refuses the ring road inside the firewall — the call is refused before the ring performs anything, and the program sees an ordinary permission error.
    match:
      action: io_uring
      io_uring: [io_uring_setup, io_uring_enter]
    tests:
      - name: a ring setup is denied
        expect: deny
        process: { pid: 1500, comm: payload, exe: /tmp/payload, argv: [payload] }
        io_uring: { call: setup }
POLICY

TRACE_UD="$WORK_DIR/trace-ud.jsonl"
status_ud=0
"$BINARY" run --approve deny --retention all --policy "$LOCAL_POLICY" --trace "$TRACE_UD" \
    -- "$WORK_DIR/uring" "$WORK_DIR/ud-marker.txt" \
    >"$WORK_DIR/ud.stdout" 2>"$WORK_DIR/ud.stderr" || status_ud=$?

assert_exit_nonzero "U6 the local deny stops the ring session" "$status_ud"
if [ -e "$WORK_DIR/ud-marker.txt" ]; then
    fail "U7 the marker of the ring write was never created"
else
    pass "U7 the marker of the ring write was never created"
fi
assert_eq "U8 the trace holds the held ring call" \
    "1" "$(afw_trace_matches "$TRACE_UD" '"type" *: *"io_uring"')"
assert_eq "U9 the local deny decided the call" \
    "1" "$(afw_trace_matches "$TRACE_UD" '"type" *: *"policy_decision".*"decision" *: *"deny"')"
assert_contains "U10 the session explains the refusal and names the rule" \
    "$(file_text "$WORK_DIR/ud.stderr")" "tamper.bypass.io-uring"
assert_contains "U11 the technique saw an ordinary permission error" \
    "$(file_text "$WORK_DIR/ud.stdout")" "blocked"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------

# The summary goes to standard error on purpose. Standard output is what a
# caller pipes away (`tests/e2e.sh | tee log`), and a reader that leaves the
# pipe early can kill the writes — the verdict must not depend on the health
# of that pipe. The exit code stays the contract: non-zero when any assertion
# failed. A caller that pipes the output reads the code with `PIPESTATUS`
# (measured: piped through `head -1`, the script died with 141 before its own
# exit, and the bare `$?` of the pipeline was the reader's 0).
printf '\n%sSummary%s\n' "$AFW_BOLD" "$AFW_RESET" >&2
printf 'passed: %d\n' "$PASS_COUNT" >&2
printf 'failed: %d\n' "$FAIL_COUNT" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '\nthe following assertions failed:\n' >&2
    for name in "${FAILED_NAMES[@]}"; do
        printf '  %s%s%s\n' "$AFW_RED" "$name" "$AFW_RESET" >&2
    done
    exit 1
fi

printf '%severy assertion passed%s\n' "$AFW_GREEN" "$AFW_RESET" >&2
exit 0
