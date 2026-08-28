# Google Antigravity agent wiped a whole drive partition during a cache cleanup

- Date: 2025-11 | Agent/tool: Google Antigravity (Gemini 3 based, running in "Turbo mode") | Axis: fs

## What happened

A designer with little coding experience used Google's Antigravity platform to build a photo-sorting tool. Antigravity ran in Turbo mode, which executes commands without asking the user each time. During the task the agent ran a command to clear the project cache. The command hit the root of the user's D: drive instead of the project folder. All files on that partition were deleted. The deletion bypassed the Recycle Bin, so the files could not be restored from the machine. The agent confirmed that the user never gave permission for the deletion and called it a critical failure. Google acknowledged the report and said it was investigating.

## How it went wrong

The agent composed a cleanup command for its project cache. The target path resolved to the root of an attached drive instead of the project folder. Antigravity executed it at once, because Turbo mode skips per-command confirmation. The delete was recursive and permanent. On Linux the same shape is a recursive delete whose path argument points at a mount or drive root, for example exec(rm, [-rf, /mnt/backup]) as a descendant of the agent process. Nothing in the tool checked the resolved path against the project folder before running it.

## What the firewall should learn

The firewall sees the delete process itself: program name, full argv, cwd, and the ancestry up to the agent. The agent product's own approval setting does not matter, because the monitor sits below it at the process level. Rule idea: a recursive delete (rm -rf, find -delete, shutil.rmtree) whose path argument is a mount root (/mnt, /media, /run/user, /Volumes) is denied, and a recursive delete of any path outside the session's work tree is gated (decision: deny for mount roots, approval_required for other outside paths). A cache-clean command from an agent should never resolve to a partition root without a human seeing it.

## Sources

- [The Register: Google's vibe coding platform deletes entire drive](https://www.theregister.com/software/2025/12/01/googles_vibe_coding_platform_deletes_entire_drive/1817705)
- [Reddit report: Antigravity deleted the contents of my whole D drive](https://www.reddit.com/r/google_antigravity/comments/1p82or6/google_antigravity_just_deleted_the_contents_of/)
- [AI Incident Database, incident 1433](https://incidentdatabase.ai/cite/1433/)
