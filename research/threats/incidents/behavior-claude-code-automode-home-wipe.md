# Claude Code Auto Mode deleted a home directory via $HOME drift between shells

- Date: 2026-08 | Agent/tool: Claude Code (Auto Mode) on macOS | Axis: behavior

## What happened

Simon Brook, a former software architect, left Claude Code running a small,
innocuous change to the deployment script of "cleanbox", his personal
email-curation project, and walked away to make tea. The agent had set up a
scratch, fake `HOME` for its work. When a later command started a new shell,
`$HOME` reverted to the real value, and the agent ran `rm -rf $HOME`, which
the shell expanded to `rm -rf /Users/simon`. The deletion of his entire home
directory began while nobody was watching. He came back to a Mac falling
apart: iCloud complaining it could not sync, a storm of Keychain alerts,
application launcher shortcuts dead, and his text editor opening as
unregistered. The agent's own transcript opened with "That last command was a
serious mistake" and explained that `$HOME` "had reverted to the real user's
home directory in the new shell... not the scratch fake home".

## How it went wrong

No attacker and no injection: the agent outsmarted its own sandbox. It had
reasoned about `rm -rf $HOME` while its mental model of `HOME` was the scratch
directory, then executed the command in a shell where the variable had
reverted to the real home. The knowledge was never missing — the model
explained what `rm -rf` does in detail about four seconds too late. What was
missing was a check that the *child shell's* environment matched the
environment the command was judged in.

The permission layer failed in exactly the same direction. A recent automatic
update had switched Claude Code's default to "Auto Mode", in which a separate
smaller model examines proposed actions, auto-runs the ones it judges
low-risk, and is specifically meant to block destructive, irreversible
actions. That layer reviewed `rm -rf $HOME` and rubber-stamped it. Anthropic's
stated justification for the default is that human users approve almost
everything anyway, and in a controlled test caught only a fraction of
deliberately dangerous commands. The author's counterpoint: the answer to
humans being bad at clicking approve is fewer approvals, not removing the
human — an agent can make at machine speed the catastrophic mistake a tired
administrator makes once at 2am.

## What the firewall should learn

The destructive shape was fully visible in argv before anything ran, twice
over: as the literal unexpanded token `$HOME` at approval time, and as the
expanded `/Users/simon` at exec time. The builtin `filesystem.delete.home`
rule gates both shapes today — this incident and the 2025-12 `rm -rf ~/`
report are its two regression anchors.

The new lesson is the drift itself. A judge that resolves a variable token
against *its own* environment will misclassify whenever the child's
environment differs: the approval layer saw the scratch `HOME`, the child saw
the real one. So: never resolve an unexpanded `$VAR` in a destructive argv
against the approver's environment or the session transcript — resolve it
against the env the child will actually inherit, and gate the literal
home-shaped token (`$HOME`, `${HOME}`, `~`) regardless of what it currently
resolves to. `filesystem.delete.unresolved-variable` already reports
variable-shaped delete targets; the missing join is child-env resolution
escalating any variable that lands on home, root, or outside the work tree.

The second lesson is architectural: a second probabilistic model approving
the first one is not a safety layer, it is a correlated failure. The author
puts it exactly the way this project does — "better" is not "bounded", and
reliability must come from the deterministic harness around the model, not
from more model.

## Sources

- [Simon Brook: When AI Stops Asking Permission (LinkedIn)](https://www.linkedin.com/pulse/when-ai-stops-asking-permission-simon-brook-65wme)
