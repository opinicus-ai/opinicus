#!/usr/bin/env bash
#
# Shared parts of the Agent Firewall demonstration.
#
# The demonstration driver (demo/run-demo.sh) and the end-to-end test
# (tests/e2e.sh) both read this file with the "." command. The file holds no
# top-level code, so it changes nothing when a script reads it.
#
# The file gives four services:
#
#   afw_setup_colors     Sets the colour variables. Colours stay empty when
#                        the output is not a terminal.
#   afw_find_binary      Finds or builds the agent-firewall binary.
#   afw_make_workspace   Makes a throwaway project with a git repository.
#   afw_trace_matches    Counts the trace lines that match a pattern.

# Sets AFW_BOLD, AFW_RED, AFW_GREEN, AFW_YELLOW and AFW_RESET.
# The variables stay empty when standard output is not a terminal, or when
# the user sets NO_COLOR.
afw_setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        AFW_BOLD=$'\033[1m'
        AFW_RED=$'\033[31m'
        AFW_GREEN=$'\033[32m'
        AFW_YELLOW=$'\033[33m'
        AFW_RESET=$'\033[0m'
    else
        AFW_BOLD=""
        AFW_RED=""
        AFW_GREEN=""
        AFW_YELLOW=""
        AFW_RESET=""
    fi
    export AFW_BOLD AFW_RED AFW_GREEN AFW_YELLOW AFW_RESET
}

# Runs git with a fixed identity, so that the throwaway repository does not
# need the configuration of the user.
afw_git() {
    git \
        -c user.name="Agent Firewall Demo" \
        -c user.email="demo@example.invalid" \
        -c commit.gpgsign=false \
        -c init.defaultBranch=main \
        "$@"
}

# Prints the path of the agent-firewall binary on standard output.
#
#   $1  Root directory of the workspace.
#   $2  "yes" to build the workspace first, "no" to use an existing binary.
#
# The environment variable AFW_BIN names an existing binary. The function
# then builds nothing.
afw_find_binary() {
    local repo_root="$1"
    local want_build="${2:-yes}"
    local binary

    if [ -n "${AFW_BIN:-}" ]; then
        binary="$AFW_BIN"
    else
        binary="$repo_root/target/release/agent-firewall"
        if [ "$want_build" = "yes" ]; then
            printf 'building the workspace: cargo build --release\n' >&2
            cargo build --release --manifest-path "$repo_root/Cargo.toml" >&2
        fi
    fi

    if [ ! -x "$binary" ]; then
        printf 'error: no agent-firewall binary at "%s"\n' "$binary" >&2
        printf 'Build the workspace first: cargo build --release\n' >&2
        printf 'Or name an existing binary: AFW_BIN=/path/to/agent-firewall\n' >&2
        return 1
    fi

    printf '%s\n' "$binary"
}

# Makes a throwaway project for the demonstration.
#
#   $1  Working directory. The function makes it when it does not exist.
#   $2  Directory that holds the demonstration scripts (demo/).
#
# The function makes:
#
#   <work>/project      A git repository with the demonstration scripts.
#   <work>/origin.git   A bare repository. It is the remote "origin".
#
# The history of the project differs from the history of the remote, so a
# normal push fails and only a force push can succeed. This makes the git
# step of the demonstration real.
#
# The function touches no directory outside the working directory. It needs
# no network and no database.
afw_make_workspace() {
    local work_dir="$1"
    local demo_dir="$2"
    local project="$work_dir/project"
    local origin="$work_dir/origin.git"

    mkdir -p -- "$project"

    if ! afw_git init --quiet -b main "$project" 2>/dev/null; then
        afw_git init --quiet "$project"
        afw_git -C "$project" symbolic-ref HEAD refs/heads/main
    fi

    cp -- "$demo_dir/agent-sim.sh" "$demo_dir/migrate.sh" "$demo_dir/schema.sql" "$project/"
    chmod +x -- "$project/agent-sim.sh" "$project/migrate.sh"

    cat >"$project/README.md" <<'EOF'
# Throwaway project

This project exists for the Agent Firewall demonstration only.
The demonstration deletes this directory again.
EOF

    afw_git -C "$project" add -A
    afw_git -C "$project" commit --quiet -m "add the migration scripts"

    afw_git init --bare --quiet "$origin"
    afw_git -C "$project" remote add origin "$origin"
    afw_git -C "$project" push --quiet origin main

    # The rewrite makes the local branch and the remote branch different.
    afw_git -C "$project" commit --quiet --amend -m "add the migration scripts (rewritten)"
}

# Counts the lines of a trace file that match an extended regular expression.
#
#   $1  Path of the trace file.
#   $2  Extended regular expression.
#
# The function prints the number on standard output. It prints 0 when the
# file does not exist.
afw_trace_matches() {
    local trace="$1"
    local pattern="$2"

    if [ ! -f "$trace" ]; then
        printf '0\n'
        return 0
    fi
    grep -c -E -- "$pattern" "$trace" || true
}
