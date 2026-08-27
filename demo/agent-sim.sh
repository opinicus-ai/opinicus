#!/usr/bin/env bash
#
# Coding agent simulator for the Agent Firewall demonstration.
#
# The script does what a real coding agent does. It runs a series of shell
# commands. Most commands are harmless. Some commands are dangerous.
#
# Usage:
#   agent-sim.sh [--safe-only]
#
# Options:
#   --safe-only   Runs the harmless steps only. Use this to show that the
#                 firewall stays quiet during normal work.
#
# Environment:
#   AFW_DEMO_GIT=1     Adds a second dangerous step: git push --force.
#                      The step needs a throwaway repository.
#   AFW_DEMO_REPO      Directory of the throwaway repository for the git
#                      step. The default is the current directory.
#   AFW_DEMO_MARKER    File that the fake psql client writes.
#
# The dangerous database step runs through a second shell. This makes the
# process chain that the project must detect:
#
#   agent-firewall -> agent-sim.sh -> bash -> migrate.sh -> psql

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="${AFW_DEMO_REPO:-$PWD}"

safe_only=0
for arg in "$@"; do
    case "$arg" in
        --safe-only)
            safe_only=1
            ;;
        *)
            printf 'agent-sim: unknown argument "%s"\n' "$arg" >&2
            exit 2
            ;;
    esac
done

step() {
    printf '\n[agent] %s\n' "$1"
}

# ---------------------------------------------------------------------------
# Part 1. Normal work. The firewall must stay quiet here.
# ---------------------------------------------------------------------------

step 'read the state of the repository'
# The step tolerates a missing repository, because the demonstration does not
# need one for this command.
git status --short --branch || printf 'agent-sim: this directory is no repository\n' >&2

step 'list the files of the project'
ls -la

step 'search for the name of the table'
grep -n "customer_archive" "$SCRIPT_DIR/migrate.sh"

step 'read the schema file'
cat "$SCRIPT_DIR/schema.sql"

step 'test the database connection'
psql -h db.prod.internal -U app -d customer_prod -c "SELECT 1"

if [ "$safe_only" -eq 1 ]; then
    printf '\n[agent] the harmless part is complete\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Part 2. Dangerous work. The firewall must stop these steps.
#
# A real agent continues after a failed command. Each dangerous step here
# therefore reports its exit code and does not stop the script. The exit code
# of the whole session comes from the firewall, not from this script.
# ---------------------------------------------------------------------------

step 'run the migration script'
# The agent starts a shell tool. The shell tool starts the script. The script
# starts psql. The firewall must follow every process of this chain.
migrate_status=0
bash -c 'cd "$1" && bash ./migrate.sh' agent-shell "$SCRIPT_DIR" || migrate_status=$?
printf '[agent] the migration script ended with code %s\n' "$migrate_status"

if [ "${AFW_DEMO_GIT:-0}" = "1" ]; then
    step 'push the rewritten history'
    # A force push can destroy the work of other people. The firewall must
    # ask before the push starts.
    push_status=0
    git -C "$REPO_DIR" push --force origin main || push_status=$?
    printf '[agent] the force push ended with code %s\n' "$push_status"
fi

printf '\n[agent] every step is complete\n'
