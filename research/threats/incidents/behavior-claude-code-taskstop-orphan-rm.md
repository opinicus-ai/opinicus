# Claude Code TaskStop left an orphaned rm -rf /c deleting for 20 minutes

- Date: 2026-08 | Agent/tool: Claude Code 2.1.222 on Windows (Git Bash) | Axis: behavior

## What happened

A developer's Claude Code session ran `rm -rf /c 2>/dev/null` through its
Bash tool. In Git Bash on Windows, `/c` resolves to the whole `C:` drive. The
agent noticed the problem after about three minutes and called TaskStop.
TaskStop reported success but killed only the shell wrapper. The `rm` child
process was orphaned and kept deleting for roughly twenty more minutes,
until the user killed it by hand. Because both the agent and the user
believed the job was stopped, nobody intervened. The agent even inspected
the disk during that window and twice reported "No damage", because it read
files the deletion had not reached yet. The wipe destroyed `~/.claude` with
all session transcripts, Desktop, Downloads, and most of Documents,
including a project with its `.git` and a second repository that existed
only locally. Two independent reproductions in the same issue showed the
same wrapper-versus-tree bug: a background loop kept launching new children
for twenty minutes, and a "stopped" LinkedIn posting script kept publishing,
posting duplicate comments.

## How it went wrong

The agent combined three mistakes. First, it issued a destructive command
with a path it did not understand: `/c` looks like a small relative
directory but is a drive root in MSYS paths. Second, it appended
`2>/dev/null`, so every permission error during the delete was hidden and
the blast radius was invisible. Third, the stop path was broken: the
harness signalled the wrapper shell, not the process tree, and returned
success. On the machine the monitor would have seen: exec of bash with argv
`rm -rf /c 2>/dev/null`, then a kill of the wrapper while the rm child kept
issuing file_open write (unlink) events under the same ancestry. The false
"stopped" signal then caused a second failure mode: replacement jobs were
started, and two workers ran at once against the same paid API and the same
output paths.

## What the firewall should learn

The firewall owns the process tree, so it can succeed where TaskStop
failed. Signals: exec argv combining a recursive delete, a single-letter
mount path like `/c`, and stderr suppression (`2>/dev/null`) should be
denied outright. Ancestry bookkeeping gives the second rule: when a session
ends or a stop is requested, enumerate surviving descendants of the agent
root and terminate them; report any that had to be killed. A third rule:
file_open write (unlink) events arriving from a process whose session root
has exited are orphans and should trigger the same teardown. The agent
destroying its own `~/.claude` transcript store is also visible as a
file_open write to the agent state directory, and deserves a deny, because
it wipes the audit trail.

## Sources

- [anthropics/claude-code issue #85200: TaskStop does not kill the process tree - orphaned rm -rf /c deleted user data for 20 minutes](https://github.com/anthropics/claude-code/issues/85200)
- [Related: #32183 Windows /exit leaves orphaned bash.exe children](https://github.com/anthropics/claude-code/issues/32183)
- [Related: #43944 background processes are not cleaned up on session exit](https://github.com/anthropics/claude-code/issues/43944)
