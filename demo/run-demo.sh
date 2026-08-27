#!/usr/bin/env bash
#
# Demonstration of the Agent Firewall.
#
# The demonstration runs three scenarios:
#
#   A  The firewall stays quiet during normal work.
#   B  The firewall stops a dangerous action inside a process chain.
#   C  The user allows the same action, and the action runs.
#
# The demonstration touches no real database and no real remote repository.
# The fake psql client in demo/bin only prints. The git steps use a
# throwaway repository inside the working directory.
#
# Usage:
#   demo/run-demo.sh [--no-build]
#
# Options:
#   --no-build   Does not run cargo. The binary must already exist.
#
# Environment:
#   AFW_BIN      Path of an existing agent-firewall binary. The script then
#                builds nothing.
#   NO_COLOR     Switches the colours off.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"

# shellcheck source=demo/lib/scenario.sh
. "$SCRIPT_DIR/lib/scenario.sh"

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

heading() {
    printf '\n%s%s%s\n' "$AFW_BOLD" "$1" "$AFW_RESET"
}

note() {
    printf '%s\n' "$1"
}

command_line() {
    printf '%s$ %s%s\n' "$AFW_YELLOW" "$1" "$AFW_RESET"
}

verdict_text() {
    if [ "$1" = "pass" ]; then
        printf '%sPASS%s' "$AFW_GREEN" "$AFW_RESET"
    else
        printf '%sFAIL%s' "$AFW_RED" "$AFW_RESET"
    fi
}

# --------------------------------------------------------------------------
# Step 1. Find or build the binary.
# --------------------------------------------------------------------------

BINARY="$(afw_find_binary "$REPO_ROOT" "$want_build")"

# --------------------------------------------------------------------------
# Step 2. Make a clean working directory with a throwaway repository.
# --------------------------------------------------------------------------

WORK_DIR="$REPO_ROOT/tmp/demo"
rm -rf -- "$WORK_DIR"
mkdir -p -- "$WORK_DIR"
afw_make_workspace "$WORK_DIR" "$SCRIPT_DIR"
PROJECT_DIR="$WORK_DIR/project"

# --------------------------------------------------------------------------
# Step 3. Put the fake client in front of PATH.
# --------------------------------------------------------------------------

export PATH="$SCRIPT_DIR/bin:$PATH"
export AFW_DEMO_REPO="$PROJECT_DIR"

heading "Agent Firewall demonstration"
note "binary:    $BINARY"
note "workspace: $WORK_DIR"
note "psql:      $SCRIPT_DIR/bin/psql (fake client, it never connects)"
note ""
note "The fake client appends a line to a marker file at the point where a"
note "real client would send the statement. A missing line proves that the"
note "program never ran."

# --------------------------------------------------------------------------
# Step 4. Scenario A. The firewall stays quiet.
# --------------------------------------------------------------------------

MARKER_A="$WORK_DIR/marker-a.txt"
TRACE_A="$WORK_DIR/trace-a.jsonl"

heading "Scenario A — the firewall stays quiet"
note "The agent runs normal commands: git status, ls, grep, cat and SELECT 1."
note "The mode is --approve deny. Every question would stop the session."
note "The session must end with code 0 and must ask nothing."
command_line "agent-firewall run --approve deny --trace trace-a.jsonl -- bash ./agent-sim.sh --safe-only"

status_a=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_A" \
        "$BINARY" run --approve deny --trace "$TRACE_A" -- bash ./agent-sim.sh --safe-only
) || status_a=$?

questions_a="$(afw_trace_matches "$TRACE_A" '"type" *: *"approval_requested"')"

result_a="fail"
if [ "$status_a" -eq 0 ] && [ "$questions_a" -eq 0 ]; then
    result_a="pass"
fi

note ""
note "exit code:           $status_a (expected 0)"
note "approval questions:  $questions_a (expected 0)"

# --------------------------------------------------------------------------
# Step 5. Scenario B. The firewall stops the dangerous action.
# --------------------------------------------------------------------------

MARKER_B="$WORK_DIR/marker-b.txt"
TRACE_B="$WORK_DIR/trace-b.jsonl"

heading "Scenario B — the firewall stops the dangerous action"
note "The agent now runs the migration script through a second shell."
note "The process chain is:"
note "  agent-firewall -> agent-sim.sh -> bash -> migrate.sh -> psql"
note "The script asks psql to drop the production database."
note "The mode is --approve deny, so the firewall answers every question with"
note "a deny. The session must end with code 3."
command_line "agent-firewall run --approve deny --trace trace-b.jsonl --print-tree -- bash ./agent-sim.sh"

status_b=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_B" AFW_DEMO_GIT=1 \
        "$BINARY" run --approve deny --trace "$TRACE_B" --print-tree -- bash ./agent-sim.sh
) || status_b=$?

drop_in_b=0
if [ -f "$MARKER_B" ] && grep -q -F "DROP DATABASE" "$MARKER_B"; then
    drop_in_b=1
fi

result_b="fail"
if [ "$status_b" -eq 3 ] && [ "$drop_in_b" -eq 0 ]; then
    result_b="pass"
fi

note ""
note "exit code:                     $status_b (expected 3)"
note "DROP DATABASE in marker file:  $drop_in_b (expected 0)"
note "marker file: $MARKER_B"
if [ -f "$MARKER_B" ]; then
    sed -e 's/^/  /' "$MARKER_B"
fi

# --------------------------------------------------------------------------
# Step 6. Scenario C. The user allows the action.
# --------------------------------------------------------------------------

MARKER_C="$WORK_DIR/marker-c.txt"
TRACE_C="$WORK_DIR/trace-c.jsonl"

heading "Scenario C — the user allows the action"
note "The scenario is the same, but the mode is --approve allow."
note "The firewall asks, the user says yes, and the statement runs."
note "The marker file must now hold the DROP DATABASE line."
command_line "agent-firewall run --approve allow --trace trace-c.jsonl -- bash ./agent-sim.sh"

status_c=0
(
    cd "$PROJECT_DIR"
    AFW_DEMO_MARKER="$MARKER_C" AFW_DEMO_GIT=1 \
        "$BINARY" run --approve allow --trace "$TRACE_C" -- bash ./agent-sim.sh
) || status_c=$?

drop_in_c=0
if [ -f "$MARKER_C" ] && grep -q -F "DROP DATABASE" "$MARKER_C"; then
    drop_in_c=1
fi

result_c="fail"
if [ "$drop_in_c" -eq 1 ]; then
    result_c="pass"
fi

note ""
note "exit code:                     $status_c"
note "DROP DATABASE in marker file:  $drop_in_c (expected 1)"
note "marker file: $MARKER_C"
if [ -f "$MARKER_C" ]; then
    sed -e 's/^/  /' "$MARKER_C"
fi

# --------------------------------------------------------------------------
# Step 7. Print the result table.
# --------------------------------------------------------------------------

heading "Result"
printf '%-3s %-38s %-34s %s\n' "ID" "Scenario" "Expected" "Result"
printf '%-3s %-38s %-34s %s\n' "--" "--------" "--------" "------"
printf '%-3s %-38s %-34s %s\n' "A" "normal work" "exit 0, no question" "$(verdict_text "$result_a")"
printf '%-3s %-38s %-34s %s\n' "B" "dangerous action, deny" "exit 3, no DROP DATABASE line" "$(verdict_text "$result_b")"
printf '%-3s %-38s %-34s %s\n' "C" "dangerous action, allow" "DROP DATABASE line present" "$(verdict_text "$result_c")"

note ""
note "The trace files stay in $WORK_DIR."
note "Read the process tree with:  $BINARY tree $TRACE_B"
note "Evaluate the trace again with:  $BINARY replay $TRACE_B"

if [ "$result_a" = "pass" ] && [ "$result_b" = "pass" ] && [ "$result_c" = "pass" ]; then
    exit 0
fi
exit 1
