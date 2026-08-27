#!/usr/bin/env bash
#
# End-to-end test of the Agent Firewall.
#
# A person or a continuous-integration job can run this test. The test builds
# the workspace, runs three sessions and checks ten assertions. The test
# writes a summary and returns a non-zero code when one assertion fails.
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
assert_contains() {
    local name="$1" haystack="$2" needle="$3"
    if printf '%s\n' "$haystack" | grep -q -F -- "$needle"; then
        pass "$name"
    else
        fail "$name" "the text holds no [$needle]"
        printf '%s\n' "$haystack" | head -n 20 | sed -e 's/^/       | /'
    fi
}

# Checks that a text does not hold a fixed string.
assert_not_contains() {
    local name="$1" haystack="$2" needle="$3"
    if printf '%s\n' "$haystack" | grep -q -F -- "$needle"; then
        fail "$name" "the text holds [$needle], but it must not"
        printf '%s\n' "$haystack" | grep -F -- "$needle" | head -n 5 | sed -e 's/^/       | /'
    else
        pass "$name"
    fi
}

# Checks that a text matches an extended regular expression.
assert_matches() {
    local name="$1" haystack="$2" pattern="$3"
    if printf '%s\n' "$haystack" | grep -q -E -- "$pattern"; then
        pass "$name"
    else
        fail "$name" "the text matches no [$pattern]"
        printf '%s\n' "$haystack" | head -n 20 | sed -e 's/^/       | /'
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
# Summary.
# ---------------------------------------------------------------------------

printf '\n%sSummary%s\n' "$AFW_BOLD" "$AFW_RESET"
printf 'passed: %d\n' "$PASS_COUNT"
printf 'failed: %d\n' "$FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '\nthe following assertions failed:\n'
    for name in "${FAILED_NAMES[@]}"; do
        printf '  %s%s%s\n' "$AFW_RED" "$name" "$AFW_RESET"
    done
    exit 1
fi

printf '%severy assertion passed%s\n' "$AFW_GREEN" "$AFW_RESET"
exit 0
