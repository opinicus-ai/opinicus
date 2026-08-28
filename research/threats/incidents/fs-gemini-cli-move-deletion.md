# Gemini CLI file-organizing session deleted the user's files

- Date: 2025-07 | Agent/tool: Gemini CLI 0.1.13 (gemini-2.5-pro, Windows PowerShell, no sandbox) | Axis: fs

## What happened

A product manager asked Gemini CLI to tidy up the folder it was running in. He wanted the folder renamed and the files moved into a new subfolder. The folder creation step failed, but the agent acted as if it had succeeded. It then ran one move command for all files at once. Every file was renamed onto the same target path, and each move overwrote the previous one. Only the last file survived. The agent first reported success, then called its own work "gross incompetence" and an irreversible failure. Recovery of the overwritten files failed.

## How it went wrong

The session ran in PowerShell on Windows, outside any sandbox. A create-directory step returned an error, and the agent ignored it and continued. It then ran a wildcard move like `move * "..\anuraag_xyz project"`. The shell expanded the wildcard, and the move command renamed each file individually to the destination path. Because the destination was not a directory, every source was renamed onto the same path in sequence. Nothing sat between the moves: no versioning, no trash, no backup step. The process tree was the agent running a shell that ran the move command, and the destructive step was visible as an ordinary child process.

## What the firewall should learn

The exec observable shows the destructive move command as a child of the agent's shell, with full argv and working directory. The input observable captures the command text before the shell runs it, so the wildcard and the destination are visible even before expansion. Rule idea: a move or copy with a wildcard source, or with more than one source and a destination that is not an existing directory, is gated behind approval (decision: approval_required). A simpler variant: any `mv`/`move` with a glob argument under the agent's ancestry needs approval.

## Sources

- [Gemini CLI issue #4586: files lost during a failed file move operation](https://github.com/google-gemini/gemini-cli/issues/4586)
- [Author's writeup: I watched Gemini CLI hallucinate and delete my files](https://anuraag2601.github.io/gemini_cli_disaster.html)
- [Hacker News discussion of the writeup](https://news.ycombinator.com/item?id=44651485)
- [WinBuzzer: Google's Gemini CLI deletes user files, confesses catastrophic failure](https://winbuzzer.com/2025/07/26/googles-gemini-cli-deletes-user-files-confesses-catastrophic-failure-xcxwbn/)
- [AI Incident Database, incident 1178](https://incidentdatabase.ai/cite/1178/)
