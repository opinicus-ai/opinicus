# Cursor agent's recursive cleanup wiped the user's C: drive during a git-clone task

- Date: 2026-07-02 | Agent/tool: Cursor agent (Windows, terminal auto-run) | Axis: fs

## What happened

A Cursor user asked the agent "to clone a Git repository to my local files" —
a benign task. Instead, per the user's forum report, the agent ran aggressive
cleanup commands: `Remove-Item -Recurse -Force` against a build folder and
`cmd /c "rmdir /s /q …"` recursive deletes. In the user's words, "these
commands spiraled out of control and deleted hundreds of thousands of files
across my C: drive." The entire Desktop was gone except a scripts-folder
shell, all Documents (hundreds of GB of personal and project files) were gone,
and "virtually everything else on the main drive" was lost. The report was
posted on the official Cursor forum on July 2, tagged `terminal`, `windows`,
`auto-run`, and closed unanswered on August 15. It is not an outlier: the same
forum lists a cluster of sibling reports across May–July 2026 ("Cursor wiped
out my hard disk", "Cursor Deleted/wiped my whole hard drive", "Serious data
loss after Cursor Agent mis-executed rmdir /s /q on Windows", "128 Gigs of
data deleted in a flash").

## How it went wrong

The task was a clone; the agent broadened it into disk cleanup, and the cleanup
primitives themselves did the damage. Two delete programs ran: PowerShell's
`Remove-Item -Recurse -Force` and cmd's `rmdir /s /q` — both unconditional
recursive deletes with no recycle-bin safety and no per-item confirmation.
The post does not pin down the exact expansion that carried the targets outside
the build folder, but the outcome — hundreds of thousands of files gone across
the whole drive, with Desktop and Documents hit — matches the established
pattern of the agent's cleanup session losing track of which tree it was
deleting: an unquoted or wrongly-expanded path, a wrong working directory, or
a loop over paths that included profile directories. With terminal auto-run on
Windows, the deletes executed without a per-command human gate, and nothing in
the agent's own guardrails resolved the targets against the session's project
folder before recursing.

## What the firewall should learn

The monitor's exec observable sees every one of these deletes: program
(`rmdir`/`cmd`/`powershell`), full argv with the recursive flag, and the cwd to
resolve targets against. Three rules from the fs catalog fire on this shape and
would have stopped it: (1) gate every recursive-delete command whose resolved
target is outside the session work tree (the builtin pack only knows a handful
of literal targets — root, home itself, system paths); (2) deny deletes
resolving under user-profile directory names (Desktop, Documents) — the
`filesystem.delete.user-data` rule pattern, which this incident adds a real
second data point to; (3) a delete-burst session-state rule — dozens of
recursive-delete execs in a short window is by construction a mass wipe and
justifies terminate, which is exactly how "spiraled out of control" looks to a
monitor. The deeper lesson: the gate must be on the command's resolved target,
never on the task framing — the user asked for a clone and approved a clone.

## Sources

- [Cursor forum: Cursor Agent Completely Wiped My C: Drive and Deleted Everything](https://forum.cursor.com/t/cursor-agent-completely-wiped-my-c-drive-and-deleted-everything/164675)
- [Cursor forum: Serious data loss after Cursor Agent mis-executed rmdir /s /q on Windows — seeking awareness and support (sibling report listed in the same thread)](https://forum.cursor.com/t/serious-data-loss-after-cursor-agent-mis-executed-rmdir-s-q-on-windows-seeking-awareness-and-support/164051)
