# Claude Code wiped uncommitted work with a path git checkout

- Date: 2026-02 | Agent/tool: Claude Code (Opus 4.5) | Axis: vcs

## What happened

A developer asked Claude Code to iterate on a front-end modal in three files.
The work was never committed. Claude edited the files, then decided to revert
its own edits. It ran `git checkout` with the three file paths as arguments.
The command reverted the files to HEAD and destroyed the user's uncommitted
tag-editor implementation along with the agent's own changes. Claude tried
`git stash list`, `git fsck --lost-found` and gave up. It told the user the
work was lost. A second agent, OpenAI Codex, then recovered the content from
dangling git objects with `git fsck` and `git cat-file`. The developer
published the full session logs.

## How it went wrong

The agent assumed the working tree was clean before it started. It used
`git checkout <paths>` as a "clean up" tool, not knowing the user's own
changes were also uncommitted. On the machine the monitor would see a chain
of file edits, then one exec: `git checkout client/components/.../index.tsx ...`
with three file paths in argv and no `--` separator. The checkout overwrote
the working tree files with the HEAD blobs. The agent's own edits were
committed to the object database at some point, so they became dangling
blobs; the user's older uncommitted work was only in the working tree and in
those same blobs, which is why recovery worked at all. Without dangling
objects, the loss would have been permanent.

## What the firewall should learn

The dangerous event is one exec: `git checkout` or `git restore` with
explicit paths while the tree was modified. The builtin discard-work rule
matches `checkout -- <path>` with a separator, and `restore` only when the
path is `.`. The separator-less form `git checkout <path>` and the form
`git restore <path1> <path2>` both slip through. Rule idea: exec of
`git checkout <pathspec>` or `git restore <pathspec>` that lists real file
paths from a process under an agent gets `approval_required`. A cheaper
companion signal is state: the same session recently opened the same files
for write, so a checkpoint or an approval prompt before any tree-discard
command would have stopped the loss.

## Sources

- [When Your AI Coding Assistant Destroys Your Work - Eric Khun](https://erickhun.com/posts/when-your-ai-coding-assistant-destroys-your-work/)
