# Claude Code cleanup command with a stray ~/ wiped a Mac home directory

- Date: 2025-12 | Agent/tool: Claude Code CLI on macOS | Axis: behavior

## What happened

A developer asked Claude Code to clean up old packages in an old repository.
The agent built a recursive delete command and ran it. The command carried a
stray `~/` argument at the end. Instead of deleting a few package folders, it
deleted the user's entire home directory. Desktop, Documents, application data
and Keychain data were gone. Around 15,000 to 27,000 files were lost,
including 15 years of family photos. The macOS Trash was bypassed, so nothing
went to the bin. Claude Code could no longer sign in afterwards, because its
own credentials lived in the deleted home directory. The story was discussed
on Hacker News and covered by tech news outlets. Anthropic reportedly tagged
the follow-up issue as `area:security` and `bug`.

## How it went wrong

This was no attacker and no prompt injection. The agent hallucinated a
cleanup target. The command it ran was `rm -rf tests/patches/plan/ ~/`. The
three intended paths were harmless; the trailing `~/` was not. A shell
expands `~/` to the home directory, and `rm -rf` deletes recursively with no
confirmation. One extra token in argv turned a repo cleanup into a full
profile wipe. Reports suggest the session ran with permission prompts
skipped, or the user approved the command without reading every argument.
Either way, the guard was a human reading argv, and the human missed one
token. The process tree was plain: agent -> bash -> rm, all with the user's
full file rights.

## What the firewall should learn

The destructive intent is fully visible in argv before rm starts. Signal:
exec(program=rm, recursive flag, any argument token that resolves to
`~`, `~/`, `$HOME`, `${HOME}`, `/Users/<name>` or `/home/<name>`). The
builtin `filesystem.delete.home` rule already gates the bare home token, so
this exact command shape is covered today; the incident is the regression
anchor for it. Rule idea: keep `approval_required` for any recursive delete
where one argument resolves to the home directory, even when other harmless
paths sit next to it in the same argv. A second lesson: an agent should
never run destructive commands with its own credential store in the blast
radius without a louder gate, because it destroys the evidence and its own
session at the same time.

## Sources

- [Gigazine: Claude Code CLI deletes your Mac's home directory](https://gigazine.net/gsc_news/en/20251216-claude-code-cli-mac-deleted/)
- [Docker blog: Coding Agent Horror Stories - The rm -rf ~/ incident](https://www.docker.com/blog/coding-agent-horror-stories-the-rm-rf-incident/)
- [Original report: Claude CLI deleted my entire home directory (r/ClaudeAI)](https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/claude_cli_deleted_my_entire_home_directory_wiped/)
- [Hacker News discussion: Claude CLI deleted my home directory and wiped my Mac](https://news.ycombinator.com/item?id=46268222)
