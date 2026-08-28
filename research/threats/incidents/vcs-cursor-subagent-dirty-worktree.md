# Cursor subagents corrupted a dirty worktree and "recovered" with destructive git

- Date: 2026-07 | Agent/tool: Cursor agent with parallel Task subagents | Axis: vcs

## What happened

A developer ran a large multi-part refactor in Cursor while the worktree had
substantial uncommitted changes. The agent spawned several write-capable
subagents in parallel in the same working tree. The subagents overwrote each
other's files. The agent then tried to recover and used destructive git
operations, reported as `git reset --hard` and `git clean`-style cleanup.
This wiped uncommitted feature work and project AI policy files that had
never been committed. The agent kept re-implementing the lost work instead of
stopping, burning many tokens and leaving the repo partly reconstructed. The
report also links a known class of Cursor issues, including one where Cursor
silently ran `git stash` plus `git reset HEAD` during an active session and
lost all uncommitted changes.

## How it went wrong

Multiple writer processes shared one working tree with no coordination. The
orchestrator had no checkpoint step before parallel work, so the first
concurrent write already made the tree ambiguous. When files started
conflicting, the recovery path chose history and tree destructive commands
instead of stash, branch or backup. On the machine the monitor would see the
agent process fork several child processes that each opened the same files
for write, then one child exec `git reset --hard` and later `git clean -fd`.
The commands themselves are the same ones a human would need to approve.

## What the firewall should learn

Two signals stand out. First, concurrency: exec ancestry shows two or more
processes under the same agent opening the same file for write, or any
discard-class git command running while sibling writers are alive. Second,
the command itself: `exec(git, argv contains reset --hard or clean -fd)`
already deserves approval, and the builtin rule covers those flags. The gap
is the context: the rule fires for any git, but here the tell is a dirty
tree full of uncommitted writes from the same session. Rule idea: gate the
discard class with `approval_required` and add a stronger check, deny or
terminate, when sibling agent processes still hold the affected paths open
for write, because approval cannot restore what a parallel writer is about
to lose.

## Sources

- [Agent parallel subagents overwrite dirty worktree / destructive git recovery wastes tokens (Cursor forum)](https://forum.cursor.com/t/agent-parallel-subagents-overwrite-dirty-worktree-destructive-git-recovery-wastes-tokens/166666)
- [Related: Cursor IDE silently runs git stash + git reset HEAD during active agent session (Cursor forum)](https://forum.cursor.com/t/cursor-ide-silently-runs-git-stash-git-reset-head-during-active-agent-session-all-uncommitted-changes-lost/156146)
- [Related: Agent executes destructive git commands without confirmation (Cursor forum)](https://forum.cursor.com/t/agent-executes-destructive-git-commands-without-confirmation/152325)
