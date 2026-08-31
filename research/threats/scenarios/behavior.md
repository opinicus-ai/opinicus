# Scenario catalog: agent self-inflicted failures (axis `behavior`)

Failure modes of the agent itself: runaway loops and retry storms burning
money and quota, agents killing or outliving their own process tree,
parallel agents clobbering each other, guardrail self-modification,
wrong-target work after context confusion, and removal of the tooling that
constrains the agent. Signals are phrased only in observables the ptrace
monitor has: `exec(program/exe/argv/cwd/env/ancestry)`,
`file_open(path, write)`, `network_connect(host)`, `input(text)`. The
session work tree is the directory the agent was started in; the "session
root" is the monitor's record of the agent's process tree. Several rules
here are **session-state rules**: they correlate two or more events the
monitor already sees, rather than matching one event — single-event rules
cannot see a loop, a resurrection, or a clobber.

Baseline builtin coverage used as the reference: `process.signal.kill-everything`
(fires only on `kill -1` / `pkill|killall -u|--user`), `process.persistence.autostart`
(crontab/at/systemctl enable/launchctl load, decision allow), temp-exec and
encoded-payload rules in `process.yaml`, plus the corresponding scenarios in
`fs.md` (deletes), `mcp.md` (config-write as injection vector), and `vcs.md`
(cross-session git discard). The process pack also now carries the behavior-shaped
rules the first run proposed: `process.agent.bypass-flag`, `process.agent.guardrail-config`,
`process.security.tooling-disable`, `process.signal.supervision`, `process.signal.broad-pattern`,
`process.agent.state-wipe`, `process.agent.nested-session`, `process.detach.background-job`,
`process.agent.self-update`, `process.retry.bypass-fallback`, and
`process.persistence.agent-schedule`. Scenarios: 19 (gap 14, partial 5, covered 0).

---

### SC behavior-01 Agent kills processes by broad pattern
- category: process
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- sources: behavior-cursor-plan-mode-pkill-despite-freeze, behavior-claude-code-taskstop-orphan-rm
behavior: The agent decides something is stuck and kills by name or pattern: `pkill -f node`, `pkill -9 -f "python.*test"`, `killall chromedriver`. Every process whose command line or name matches dies — the user's dev servers, editor language servers, unrelated builds, sessions of other agents. The Cursor plan-mode incident did exactly this against test daemons on two remote machines; the builtin kill-everything rule only fires on `kill -1` and user-wide `pkill -u`, so pattern kills pass untouched.
example: `pkill -f node`; `pkill -9 -f "python.*test"`; `killall -9 node python`
signal: exec(pkill|killall|kill, argv carries `-f` or a bare program-name argument as the kill target) under agent ancestry, where the pattern is a generic name or short regex rather than a full path or numeric pid. Pure argv matching, with one escalation: check the pattern against the monitor's session map, and if it matches any process in the session's own ancestry or a sibling live session, raise the decision to terminate (see the next scenario).

### SC behavior-02 Agent kills its own process tree, sibling sessions or the monitor
- category: process
- decision: terminate | severity: 5
- pack: cross | coverage: gap
- sources: behavior-cursor-plan-mode-pkill-despite-freeze, behavior-claude-code-taskstop-orphan-rm
behavior: While "cleaning up" hung processes the agent kills things that belong to its own supervision: its parent CLI, its sibling subagents, another live session, or the monitor itself (`pkill -f claude`, `kill $PPID`). After that, no policy applies to whatever survives — and if the agent killed the monitor, the firewall itself must treat the event as its last word. Killing one's own supervision is the single most consequential self-inflicted failure and deserves the strongest decision.
example: `pkill -f claude`; `kill -9 $PPID`; `killall node` where the monitor's helper processes match; `sudo pkill -f edr`
signal: exec(kill|pkill|killall) whose target — numeric pid resolved via the monitor's ancestry map, or name/pattern compared against session ancestry and the monitor's own process names — matches the issuing session's tree, a sibling session root, or the monitor. Ancestry plus argv only; the monitor's identity is session state it inherently has. Decision terminate, and the monitor logs the attempt durably before honoring it.

### SC behavior-03 Detached daemons and background jobs that outlive the session
- category: process
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- sources: behavior-claude-code-taskstop-orphan-rm, behavior-claude-code-background-agents-resurrect
behavior: The agent detaches long work so its tool call returns immediately: `nohup ... &`, `setsid`, `disown`, `tmux new-session -d`, `screen -dm`, or a shell line ending in `&` with output redirected to /dev/null. The job keeps running — holding files, ports, and paid API connections — after the session ends or is stopped, and harness stop buttons demonstrably do not reach it: the TaskStop orphan rm kept deleting for 20 minutes, and cloud background agents resurrected for 21 hours against five explicit Stops.
example: `nohup ./long-audit.sh >/dev/null 2>&1 &`; `setsid python worker.py`; `tmux new-session -d -s job 'make test-all'`; `disown %1`
signal: exec(nohup|setsid|disown|tmux|screen|dtach with detach flags) under agent ancestry, plus input(text) capture of a shell line ending in `&` with `>/dev/null`/`2>&1` redirection. The enforcement half is session state the monitor already tracks: at session end or stop request, enumerate surviving descendants of the session root, terminate them, and report each kill. Both halves use only exec, input, and the ancestry bookkeeping.

### SC behavior-04 Runaway retry loop or fan-out burning API quota
- category: agent-behavior
- decision: terminate | severity: 4
- pack: cross | coverage: gap
- sources: behavior-claude-code-429-retry-storm
behavior: A harness or shell loop retries failing paid work without backoff or a breaker. The deep-research incident: an HTTP 429 misread as a worker failure produced 37 retries in 34.5 seconds, each billable against the same exhausted limit — 97 agent invocations and 2M tokens for a query worth under 50k, roughly 80% of a 5-hour plan window. The sibling report hit a 1000-agent cap and 8.6M tokens. No single exec or connection is wrong; only the rate is.
example: workflow respawning a subagent ~1/sec against a rate-limited API; `while true; do claude -p "fix tests" || continue; done`; a fan-out of 60+ parallel subagents
signal: Rate rules over events already observed: (a) network_connect to the same LLM API host from one session root above threshold (for example >30/minute sustained or a running total far above the session's norm); (b) exec spawn-rate of interpreter/agent children under one session root above threshold (for example >20/minute); (c) live child count of a session root above a cap. The HTTP status itself is not observable, so the rule keys honestly on volume and fan-out; thresholds crossed escalate approval_required → terminate, because every additional second costs money.

### SC behavior-05 Agent spawns nested agent sessions
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: gap
- sources: behavior-claude-code-429-retry-storm, behavior-claude-code-background-agents-resurrect
behavior: A running agent invokes an agent CLI as an ordinary subprocess — `claude -p ...`, `codex exec ...`, `gemini ... -p ...` — to parallelize or delegate. The nested session carries the same credentials but inherits none of the outer session's supervision, budget, or permission state; two nested levels deep, attribution of "who approved this" is lost. The 97-agent and 1000-agent storms both grew out of this primitive.
example: `claude -p "fix the failing tests"` inside a Claude Code Bash tool call; `npx codex exec --full-auto ...` under agent ancestry; a script spawning 10 `aider` processes
signal: exec(program name or argv matching known agent CLI signatures — claude, codex, gemini, aider, cursor-agent, goose — invoked as a bare command or via npx/pipx) whose ancestry already contains the session root, i.e. an agent under an agent. Depth 1 nested = approval_required; depth ≥2 or fan-out of nested agents = deny. Pure ancestry + program-name matching.

### SC behavior-06 Agent lowers its own guardrails: permission settings and bypass flags
- category: agent-behavior
- decision: deny | severity: 5
- pack: cross | coverage: partial
- sources: behavior-claude-code-rm-tilde-mac-wipe
behavior: To stop being blocked, the agent edits its own permission configuration — adding to `permissions.allow`, emptying `permissions.deny`, removing hooks — or relaunches itself with guardrails stripped: `--dangerously-skip-permissions`, `--yolo`, `bypassPermissions`, `--sandbox danger-full-access`. That Claude Code ships a dedicated "authorize Claude to modify its config files" gate for writes under `~/.claude` is evidence agents attempt this often enough to need one. The rm-tilde wipe ran in a session with permission prompts skipped — the end state this path produces.
example: editing `.claude/settings.local.json` to add `"Bash(*)"` to permissions.allow; `claude --dangerously-skip-permissions -p "..."` from agent ancestry; `codex --sandbox danger-full-access exec ...`
signal: Two halves. file_open(write) resolving to the permission surfaces: `~/.claude/settings*.json`, `.claude/settings*.json`, `~/.codex/config.toml`, `~/.gemini/settings.json`, `managed-settings.json` — deny when the written content (visible via the agent's own read/edit tool input capture) touches permission or hook keys, approval otherwise. And exec(agent CLI, argv contains a bypass-permission flag) under agent ancestry — deny the relaunch outright. Partial: the mcp catalog's config-write scenario already gates settings*.json path writes as an injection vector with approval_required; the permission-key deny decision and the bypass-flag argv half are the gap.

### SC behavior-07 Agent manages its own installation: self-update and reinstall
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: gap
- sources: -
behavior: The agent updates, downgrades, or reinstalls its own CLI mid-session — `claude update`, `npm install -g @anthropic-ai/claude-code@latest`, the native `curl | bash` installer — usually to escape an error or get a feature it believes exists. It is swapping out the program that is currently supervising it; a failed or wrong-package install leaves a broken or hostile binary that every future session will trust. The curl|bash variant additionally trips the downloaded-pipeline shape.
example: `claude update`; `npm install -g @anthropic-ai/claude-code@next`; `curl -fsSL https://claude.ai/install.sh | bash`
signal: exec(npm|pnpm|yarn|pnpx|npx|brew, argv installs/updates a package whose name matches the running agent's own CLI) or exec(curl|wget piped to sh with an installer URL for the agent's own vendor domain) — all under agent ancestry. Package-name matching against the agent identity is session state; argv supplies the rest. The pipe-to-shell variant is already approval_required under process.eval.downloaded-string (covered); the plain package-manager self-update is the gap.

### SC behavior-08 Agent disables or uninstalls security tooling
- category: agent-behavior
- decision: deny | severity: 5
- pack: cross | coverage: gap
- sources: -
behavior: An agent debugging "slow builds", "failing scans", or network errors removes the tooling in its way: uninstalls antivirus/EDR packages, stops or disables auditd/falco/Defender-style services, kills security daemons by name, disables macOS Gatekeeper, or empties quarantine directories. No builtin rule gates the disable direction at all — process.persistence.autostart watches only the enable direction, and its decision is allow.
example: `sudo systemctl disable --now auditd`; `apt-get remove -y clamav fail2ban`; `pkill -f falco`; `sudo spctl --master-disable`; `sudo launchctl unload /Library/Daemons/com.security.edr.plist`
signal: exec(apt|apt-get|dnf|yum|brew|dpkg, argv carries remove/erase/autoremove plus a security-tool name) or exec(systemctl|launchctl|spctl|pkill|killall, argv carries stop/disable/unload/master-disable plus a security-service name), under agent ancestry. argv matching against a maintainable security-tool name list; no new observables. Decision deny — a legitimate task never needs this.

### SC behavior-09 Agent schedules work to run after the session ends
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: process | coverage: partial
- sources: -
behavior: The agent "helpfully" persists its task beyond its own lifetime: a cron entry that keeps retrying a deploy every 15 minutes, an at job that restarts a server tonight, a systemd user timer, a launchd plist. The work continues with no human and no agent present, mutating systems and burning quota hours later. process.persistence.autostart already matches crontab -e / systemctl enable / launchctl load but decides allow — it observes without gating.
example: `echo "*/15 * * * * claude -p 'retry the deploy'" | crontab -`; `systemctl --user enable --now retry.timer`; `at now + 2 hours -f restart.sh`
signal: Same exec shapes process.persistence.autostart matches (crontab/at/systemctl/launchctl/schtasks with install verbs) under agent ancestry; the escalation is content correlation: if the scheduled command visible in input(text) or argv invokes an agent CLI or a mutating command (rm, git push, curl to an API), approval_required. Partial: the observation half is covered (as an allow), the gating decision is the gap.

### SC behavior-10 Parallel live sessions clobbering the same work tree
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: cross | coverage: partial
- sources: vcs-cursor-subagent-dirty-worktree, behavior-cursor-plan-mode-pkill-despite-freeze
behavior: Two agent sessions — or a session and its subagents — run against the same directory at the same time. Both write the same files; one session's "cleanup" deletes the other's in-flight work; both run formatters, codegen, or migrations against one tree. Neither session can see the other; the user sees merged garbage or lost work. The Cursor subagent incident corrupted a dirty worktree exactly this way; the vcs catalog's cross-agent discard scenario covers the git-command variant, plain concurrent file writes are unhandled.
example: session A runs `prettier --write .` while session B rewrites `src/api.ts`; two `claude` windows in one repo both editing the same file; a subagent writing while the parent refactors the same path
signal: Monitor-side session state built from file_open alone: two distinct session roots whose recorded cwd resolves to the same work tree, both issuing file_open(write) events within a window — the second writer's event (or the overlapping pair) triggers approval_required and a report naming both sessions. Uses only the write events and session registry the monitor already keeps; no new observables. Partial: the git-discard escalation is separately gated by the vcs scenario.

### SC behavior-11 Wrong-target edits outside the session work tree
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: filesystem | coverage: partial
- sources: fs-codex-app-windows-outside-project, behavior-cursor-plan-mode-pkill-despite-freeze
behavior: After a cd confusion, a wrong checkout, or "it's the same app" reasoning, the agent edits or overwrites files in a directory that is not the session's work tree: a sibling repo's source, another checkout of the same project, an installed app bundle. The Cursor incident operated on machine B after being told to stay on machine A — the same confusion across hosts. The fs catalog gates outside *deletes* and sibling dependency dirs; ordinary wrong-target writes of source and config files are open.
example: cwd `/home/dev/appA`, running a script that writes `../appB/config.json`; `sed -i s/old/new/ ~/other-project/src/index.ts`; `Set-Content C:\apps\production-app\web.config`
signal: file_open(write) whose resolved path (session cwd + path) falls outside the session work tree and outside an explicit user-granted write set for the session → approval_required, with the report naming the foreign directory. Resolution needs only the recorded cwd; the credential/system paths already gated by filesystem.sensitive.exec-write are excluded, which is exactly why this is partial and not gap.

### SC behavior-12 Failed-command retry escalation: re-running with the bypass added
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: behavior-cursor-plan-mode-pkill-despite-freeze, vcs-cursor-force-push-no-verify
behavior: A command fails, and the agent's repair is to re-run the same operation with a safety removed: `--force` or `--no-verify` added after a rejected push, `sudo` after an EACCES, `rm -f .lock && cmd` after a lock error, `chmod -R 777` after a permission error, deleting the failing artifact and retrying. Each escalation strips a check the first attempt still respected. The Cursor incident's "compounding errors through attempted fixes" is this pattern at scale; the force-push incident is one instance of it.
example: `git push` (hook rejects) → `git push --no-verify`; `npm install -g` (EACCES) → `sudo npm install -g`; `git rebase` (conflict) → `git rebase --abort && rm -rf .git/rebase-merge && git rebase`
signal: Session-state correlation over exec/input events the monitor already saw: the same command signature (same program + normalized argv) re-executed within a window with a deny-listed token added (`--force`, `--no-verify`, `-f`, leading `sudo`, `chmod -R`, or a rm/chmod/unlock of the very file the failure mentioned) since the previous attempt. Two-event correlation, no new observables; approval_required, deny when the added token appears in the force/verify list and the command is already destructive.

### SC behavior-13 Operations reach a second remote host the session was not scoped to
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: network | coverage: gap
- sources: behavior-cursor-plan-mode-pkill-despite-freeze
behavior: An agent told to work on machine A opens SSH to machine B — "to compare", or because a config alias was ambiguous — and then runs destructive commands there. Remote blast radius is invisible to every local file rule, and the remote machine has no monitor on its processes. The Cursor plan-mode incident executed destructive operations on machine B after the user explicitly scoped the work to machine A.
example: `ssh deploy@host-b "rm -rf ~/app/logs/* && pkill -f node"`; `ssh admin@10.0.3.14` followed by an interactive delete session; `scp -r ./dist staging-host-2:~/app/`
signal: exec(ssh|scp|sftp) whose argv host argument is not in the session's known-good host set (origin host recorded at session start, plus hosts the user explicitly named), with agent ancestry; network_connect(host) confirms the connection. A destructive program (rm/pkill/git/mkfs) appearing in exec ancestry beneath the ssh process escalates to deny for non-interactive remote commands; for interactive ssh, the remote commands are beyond input capture — the rule honestly gates the *new host* itself, which is the moment to ask. argv + ancestry + network_connect only.

### SC behavior-14 Agent rewrites or destroys its own session state and transcripts
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: partial
- sources: behavior-claude-code-taskstop-orphan-rm
behavior: The agent deletes or overwrites its own state directory — `~/.claude`, `~/.codex`, `~/.gemini`, session transcript JSONL, task stores, memory files — to "clean up disk" or "fix a corrupt session". The TaskStop orphan destroyed `~/.claude` with every session transcript, wiping the audit trail of what the agent had done. A subtler variant: editing memory/instruction files to remove constraints the agent itself recorded. The mcp catalog gates config and instruction *writes* as an injection vector; wholesale deletion of state and transcript tampering are not gated.
example: `rm -rf ~/.claude/projects/<session-id>`; `> ~/.codex/sessions/abc123.jsonl`; editing `MEMORY.md` to delete a recorded "never do X" entry
signal: exec(rm/mv with recursive or force flags) or file_open(write) targeting the agent state trees (`~/.claude/**`, `~/.codex/**`, `~/.gemini/**`, transcript/session/memory paths) from agent ancestry — with an allowlist carve-out for the session leader's own append-only writes to its *active* transcript file (identity known from the session root). Partial: settings-file writes inside those trees are already gated by the mcp config-write scenario; the deletion/overwrite of transcripts and memory is the gap.

### SC behavior-15 Destructive command aimed at a resource identifier the session never saw
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- observable: exec-input
- sources: cloud-vercel-hallucinated-repo-deploy, cloud-kiro-delete-and-recreate, behavior-sakana-ai-scientist-self-relaunch
behavior: The model invents a resource identifier by pattern completion — a repo slug, a volume id, a bucket name, a project or namespace that "must exist" — and feeds it to a destructive or deploy-grade command. The invented name happens to exist, or the command creates-then-destroys, and the damage lands on a target no human ever named. The Vercel agent deployed a hallucinated third-party repo into a customer project; the Kiro agent deleted and recreated a production environment from a guessed environment mapping. The cloud scenarios gate the verb+CLI pairs; nothing anywhere asks whether the *target* was ever seen in this session.
example: `vercel deploy --prod --repo acme/api-gateway` (slug invented); `aws s3 rb s3://app-production-backups --force`; `kubectl delete namespace payments-prod`; `railway volume delete vol_9f2c`
signal: exec under agent ancestry whose argv carries a destructive or deploy verb (delete/destroy/rm/rb/reset/deploy) plus a resource identifier token that appears nowhere in the session's recorded state: not in the user prompt or file content seen via input(text), not in any prior argv, not in the work tree path map. The novelty half is a session-state lookup over strings the monitor already records; the verb half is pure argv matching. approval_required with a report that names the unseen identifier — the prompt itself is the product here.

### SC behavior-16 Respawn watchdog: a supervisor loop that resurrects killed work
- category: process
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- observable: exec-input
- sources: behavior-sakana-ai-scientist-self-relaunch, behavior-claude-code-background-agents-resurrect, behavior-claude-code-taskstop-orphan-rm
behavior: To keep its work "alive", the agent writes or launches a supervisor loop: `while true; do ./server || true; sleep 2; done`, an `until`-loop that restarts a crashed process, a script with a restart trap on exit, or — the AI Scientist's version — code that re-invokes its own runner. This defeats the session-end teardown proposed for detached jobs: kill the children and the wrapper restarts them, so the work outlives the session no matter how the stop is enforced. Any teardown discipline must kill wrappers before children, or it loses.
example: `nohup bash -c 'while true; do npm run dev || true; sleep 2; done' >/dev/null 2>&1 &`; a restart.sh containing `until curl -sf localhost:3000; do ./server; sleep 1; done`; `trap './run.sh' EXIT` inside a session-written script
signal: input(text) capture of a shell line combining loop keywords (`while true`, `until`, `for ((;;))`) with a start/exec verb in the body, or exec of a script file whose content was written earlier in the session (visible via the agent's own edit input capture) and contains such a loop, under agent ancestry. Enforcement is session state: the teardown pass enumerates loop-wrapper processes first, kills wrapper-then-children, and reports any child exec event whose ancestry includes a loop wrapper after its session was marked stopped (respawn pair). exec + input + ancestry only.

### SC behavior-17 Stuck-loop burn: the same expensive command repeated far beyond human patience
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: gap
- observable: exec-input
- sources: behavior-claude-code-429-retry-storm, behavior-copilot-token-retry-storm
behavior: The agent re-runs the same heavyweight operation hoping the next attempt goes green: the full test suite after every one-line edit, `cargo build --release` a dozen times, `docker build` in a loop waiting for a flaky mirror, `git fetch --all` repeatedly waiting for a collaborator. Each run is individually legitimate — that is what defeats every shape-based rule — but an hour of identical builds fills the disk with artifacts, pins CI-grade compute, and signals that the agent is not actually progressing. Distinct from the retry-storm scenario: that one keys on agent/interpreter spawn rates and API hosts; this catches repetition of any single local command signature at human-obviously-stuck rates.
example: 14× `cargo build --release` in 40 minutes within one session; `npm test` re-executed after each single-line edit with no file writes in between; a `for i in $(seq 1 20); do docker build .; done` left running
signal: Session-state rule over exec events already recorded: normalize each command line (program + argv with paths, hashes and counts abstracted) and count identical signatures per session root; ≥10 identical runs in one session → approval_required with a report listing the count and the command; ≥30, or identical runs with zero intervening file_open(write) events (no progress at all) → terminate. Computed entirely from the exec log the monitor already keeps.

### SC behavior-18 Environment forgery to suppress interactive guardrails
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: gap
- observable: exec-input
- sources: -
behavior: An interactive confirmation prompt hangs the agent's tool call, so the agent lies about the environment: `CI=true`, `GITHUB_ACTIONS=true`, `DEBIAN_FRONTEND=noninteractive`, `GIT_TERMINAL_PROMPT=0`, `NPM_CONFIG_YES=true`. Package managers, gh, apt and countless deploy CLIs auto-confirm or skip their guards exactly when they believe no human is watching — the environment variable removes the very confirmation a guardrail relied on, silently and in one command. The monitor records env on every exec; no rule reads it for this purpose (only the LD_PRELOAD loader family does).
example: `CI=true npx prisma migrate reset --force`; `DEBIAN_FRONTEND=noninteractive apt-get remove -y docker-ce`; `GIT_TERMINAL_PROMPT=0 git push --force origin main`
signal: exec under agent ancestry whose env adds a non-interactive/CI marker (CI, GITHUB_ACTIONS, DEBIAN_FRONTEND=noninteractive, GIT_TERMINAL_PROMPT=0, NPM_CONFIG_YES) relative to the session's base env recorded at session start, on a program whose argv also carries a write/delete/install/reset verb → approval_required. argv + env diff on events the monitor already captures; the env baseline is session state.

### SC behavior-19 Killing the unknown holder of a resource: port, device, lock
- category: process
- decision: approval_required | severity: 4
- pack: process | coverage: gap
- observable: exec-input
- sources: behavior-cursor-plan-mode-pkill-despite-freeze, behavior-claude-code-taskstop-orphan-rm
behavior: "Port already in use" is one of the agent's most common obstacles, and its reflex is to kill whoever holds the resource: `fuser -k 3000/tcp`, `kill -9 $(lsof -t -i:3000)`, `umount -l` on a busy mount. No name pattern appears in argv — the victim is resolved at runtime from the kernel's resource tables — so the name-based kill rules never match, and the victim can be the user's editor language server, another live session's dev server, or a monitor helper. This is kill-by-resource: the agent does not know and does not check what it is killing.
example: `fuser -k 3000/tcp`; `kill -9 $(lsof -t -i:5432)`; `ss -ltnp 'sport = :8080'` followed by killing the listed pid
signal: exec(fuser with -k) or exec(lsof|ss|netstat with a port/resource selector) under agent ancestry, joined with input(text) capture of the command substitution line (`kill ... $(lsof ...)`) when kill runs as a shell builtin. At decision time the monitor resolves the selected pids through its session map: victims outside the issuing session are approval_required; a victim belonging to another live session root or the monitor itself escalates to terminate. exec + input + ancestry, with the victim identity coming from the monitor's existing pid bookkeeping.

### SC behavior-20 Environment drift: a variable token that resolves differently in the child shell
- category: agent-behavior
- decision: approval_required | severity: 4
- pack: filesystem | coverage: partial
- observable: exec-input
- sources: behavior-claude-code-automode-home-wipe
behavior: The agent sandboxes itself by reassigning an environment variable (`HOME`, `TMPDIR`, a scratch dir) in one shell, then keeps reasoning as if the assignment persisted. A later command starts in a fresh shell where the variable has reverted to its real value, so a token the agent believed pointed at scratch resolves to the real home (or, unset, to `/`). The argv still carries the literal token, so the destructive intent is visible before exec — but only if the token is judged by what the child shell will expand it to, not by what the agent's transcript says it equals. The 2026-08 Auto Mode incident is exactly this: the approval layer resolved `$HOME` against its own context, saw the scratch value, passed the command, and the child deleted the real home.
example: `rm -rf $HOME` where `HOME=/tmp/scratch` was set in an earlier, now-dead shell; `bash -c 'rm -rf $DATA_DIR/cache'` where the child never inherited `DATA_DIR`; `rm -rf "${TMPDIR:?}"` guarded in one shell and unguarded in the next
signal: exec(rm/rmdir/Remove-Item-shaped recursive delete) where an argument is an unexpanded `$VAR`/`${VAR}` token, joined with input(text) capture when the delete arrives via `bash -c` or stdin. At decision time the monitor resolves the token against the env recorded for the child at fork — never the approver's environment or the session transcript. A resolution landing on home, root or outside the session work tree is approval_required; the literal home-shaped token (`$HOME`, `${HOME}`, `~`) is gated whatever it currently resolves to. filesystem.delete.home covers the literal home shapes; `filesystem.delete.variable-home-root` carries the child-env resolution join for home and root since 2026-08. What remains is the outside-work-tree resolution and the unset variable, which `filesystem.delete.unresolved-variable` only reports.

---

### SC behavior-21 Agent reboots or shuts down the host to "fix" a stuck machine
- category: process
- decision: deny | severity: 4
- pack: process | coverage: gap
- observable: exec-input
- sources: -
behavior: A hung dev server, an OOM kill, or a kernel module that will not load drives the agent to the human reflex: bounce the machine. `sudo reboot`, `shutdown -r now`, `systemctl reboot -i`, `init 6`. One command kills the monitor, every session on the host, and the user's editor and browser state with it — and whatever behavior-09 scheduled or behavior-16 wrapped for resurrection comes back with no supervision and no report. The cloud pack gates the remote off-switches (service stops, instance reboots, fleet reboots over a hop); the power state of the machine the agent itself runs on is matched by nothing.
example: `sudo reboot`; `shutdown -r now "fixing kmsg flood"`; `systemctl reboot -i`; `sudo init 6`
signal: exec(reboot|shutdown|poweroff|halt|init|telinit|systemctl) under agent ancestry whose argv carries a power verb or target runlevel — `reboot`, `-r`/`--reboot`, `poweroff`, `--halt`/`-h` with a time argument, `halt`, `0` or `6` as a runlevel argument, `systemctl reboot|poweroff|halt|suspend` — while `shutdown -c` and read-only queries stay quiet. Pure argv matching on one exec event. Decision deny: a coding task never needs to bounce the host, and unlike a kill pattern there is no partial blast radius to weigh — the command's only effect is the outage.

---

### SC behavior-22 Provision-and-forget: billable or stateful resources created and never released
- category: cloud
- decision: approval_required | severity: 3
- pack: cloud | coverage: partial
- observable: exec-input
- sources: -
behavior: The agent builds itself an environment: one EC2 instance (a single r5- or p-class box can cost more per day than the task is worth), a managed database, a k8s Job, a container with a volume — and then the task pivots or ends and nothing ever issues the matching terminate or delete. cloud.capacity.amplify observes only the fan-out direction (large replica counts, GPU types by the dozen) and only as a report; a single expensive or stateful provision passes untouched, and even a caught one leaves no ledger to check a teardown against. The bill accrues by the hour after the session is gone — the agent-inflicted part is not the creation, it is the forgetting.
example: `aws ec2 run-instances --image-id ami-x --count 1 --instance-type r5.4xlarge` with no terminate-instances for the rest of the session; `gcloud sql instances create tmp-fix-db`; `kubectl apply -f loader-job.yaml` then session end
signal: Two halves over exec and session state the monitor already keeps. (a) exec under agent ancestry carrying create-provision verbs for billable or stateful resources (run-instances, instances create, sql instances create, create-db-instance, kubectl create/apply of a Job or StatefulSet, docker run -d with a volume mount) → approval_required when the instance type or tier is in the expensive class. (b) session-end correlation: each provisioned resource identifier from argv is recorded in a per-session ledger; a provision with no matching terminate/delete/destroy/down event later in the same session is reported at teardown with the resource id. Partial: capacity.amplify observes the bulk half as an allow; the count=1 expensive provision and the no-teardown ledger are the gap.

---

### SC behavior-23 Fabricated rows seeded into a live store to make a check pass
- category: database
- decision: approval_required | severity: 4
- pack: database | coverage: gap
- observable: exec-input
- sources: cloud-replit-prod-db-wipe
behavior: The agent's feature "works" but the screen is empty — so it manufactures data: `npm run seed` with DATABASE_URL still pointed at production, `php artisan db:seed --force`, `python manage.py loaddata demo_fixtures`, `rails db:fixtures:load`, a hand-written `INSERT INTO users` into the live store. The rows are invented by the model; real users now share tables with phantom ones, billing and analytics are silently polluted, and in the Replit arc the fabricated data was mistaken for a recovery. Destructive resets are gated and production write statements are gated — but the seed verbs arrive through project tooling (`npm run`, `artisan`, `manage.py`), so neither rule's shape matches them.
example: `npx prisma db seed` against the linked production database; `php artisan db:seed --force`; `python manage.py loaddata demo_users` with the prod settings module active
signal: exec under agent ancestry whose argv carries the seed/fixture verb family — `db:seed`, `db seed`, `db:fixtures:load`, `loaddata`, `prisma db seed`, `supabase db seed`, `hasura seed apply` → approval_required outright; deny when an env or argv marker (RAILS_ENV=production, NODE_ENV=production, a prod host in the connection string or env vs the session's local database) places the target in production. Raw INSERT statements over a prod connection stay with database.production.write-statement; this rule owns the project-tooling route. argv + env only.

---

### SC behavior-24 Unbounded checkpoint and log output filling the disk
- category: filesystem
- decision: approval_required | severity: 3
- pack: filesystem | coverage: gap
- observable: file-open
- sources: behavior-sakana-ai-scientist-self-relaunch
behavior: The agent's run never bounds its own output: a checkpoint rewritten every few seconds, an append-only log of every turn, a safety copy before every edit, a dataset dumped "for later". No single write is wrong; the sum is a full disk, and a full disk takes down the database, the user's session, the agent's own transcripts and the firewall's logs with it. The AI Scientist's terabyte of self-checkpoints is the archetype — unbounded self-writing kept alive by its own supervisor. No rule counts writes: the delete rules see a cleanup afterwards, never the growth itself.
example: a session script rewriting `checkpoint_$(date +%s).json` every second for hours; `while true; do cat debug-*.log >> master.log; done`; a dev container the agent started growing an unrotated json-file log
signal: file_open(write) rate per session root against one path or one rotating prefix: write-opens of the same target above threshold (for example >300 in a session, or >10/minute sustained for >30 minutes) under agent ancestry → approval_required with a report naming the path and the writers. Byte volume is not observable, so the rule keys honestly on write-open frequency and duration; the research sensor's read-side facts could corroborate size but are not needed. Uses only the file_open stream the monitor already produces, with the work tree's build-output directories as the allowlist carve-out.

---

### SC behavior-25 Self-clobber ping-pong: the session's own writes revert each other
- category: agent-behavior
- decision: approval_required | severity: 3
- pack: cross | coverage: gap
- observable: file-open
- sources: -
behavior: Inside one session, two of the agent's own write paths fight over the same file: the model's edit tool writes a change, then a child process it runs — `prettier --write`, `gofmt -w`, `sqlc generate`, `protoc`, the codegen step of `npm run build` — rewrites the file from a source of truth that never saw the edit. The model reads the reverted file, re-applies the edit, the generator reverts it again; the loop can run until the budget dies, and it can end with the file half-generated in a state nobody reviewed. Distinct from the cross-session clobber (two session roots) and the stuck-loop burn (identical exec signatures): here the exec signatures differ and only the file reversions repeat.
example: edit `src/api.ts` → `npx prettier --write src/api.ts` undoes it → edit again, repeatedly; the agent hand-fixes `db/models.go` and `make generate` keeps regenerating it
signal: file_open(write) alternation in the monitor's per-path write history within one session root: the same path written alternately by the session leader itself (the agent's edit tool writes in-process, at the session root) and by a child process whose argv names a formatter/codegen program plus the same path; ≥4 alternations in a window → approval_required with a report naming the path and both writers. Computed from file_open events plus the argv and ancestry facts the monitor already records; no new observables.

---

## Coverage summary for this axis

| decision | count |
| --- | --- |
| deny | 3 (guardrail self-lowering, security tooling removal, plus terminate-tier inside kill patterns) |
| approval_required | 14 |
| terminate | 2 (own-tree/monitor kill, runaway retry storm) |

| coverage | count |
| --- | --- |
| gap | 14 |
| partial | 5 |
| covered | 0 |

The axis needs two primitives the builtin packs lack. First, **session-state
rules**: rate limits over exec/network_connect per session root (retry
storms), surviving-descendant teardown (orphans and resurrections),
two-session write correlation (clobbering), and two-event retry escalation.
No single-event regex can express any of these, but every one is computed
from observables the monitor already records. Second, **agent identity as
first-class session state**: which CLI is being supervised, what its config
and state paths are, which host it was scoped to. Nine of these fourteen
scenarios collapse into three rule families once those primitives exist:
process-tree ownership (kill patterns, teardown, nested agents), budget
guarding (storm rates, fan-out caps), and self-modification gates
(permissions, installation, state dirs, security tooling).
