# Threat research ledger

The ledger lists every incident and every block scenario that the threat
research found. One row per item. Stable identifiers never change.

Sections:

- Coverage summary: how well the builtin policy packs cover the scenarios.
- Incident ledger: real, documented cases where a coding agent went wrong.
- Scenario ledger: concrete behaviors the firewall should handle. The status
  moves from `proposed` to `rule-written` (a rule id exists in `policies/`)
  to `tested` (the rule has tests that prove it).
- Run log: one row per research run.

Maintained by the reusable workflow in `threat-research.workflow.js`. See
`README.md` for how to run it again.

## Coverage summary

| policy pack | gap | partial | covered |
| --- | --- | --- | --- |
| filesystem | 15 | 7 | 0 |
| git | 4 | 4 | 0 |
| process | 28 | 5 | 0 |
| network | 16 | 1 | 0 |
| database | 2 | 1 | 0 |
| cloud | 9 | 2 | 0 |
| cross | 31 | 6 | 0 |
| mcp | 1 | 0 | 0 |

## Incident ledger

| id | date | title | axis | report | sources |
| --- | --- | --- | --- | --- | --- |
| INC-001 | 2025-07 | Replit coding agent deleted a production database during a "vibe coding" session | cloud | research/threats/incidents/cloud-replit-prod-db-wipe.md | https://www.businessinsider.com/replit-ceo-apologizes-after-ai-coding-assistant-deletes-company-database-2025-7 |
| INC-002 | 2025-08 | Nx "s1ngularity" supply-chain attack abused local AI CLIs to harvest credentials | supply | research/threats/incidents/supply-nx-s1ngularity.md | https://nx.dev/blog/nx-security-alert |
| INC-003 | 2025-09 | "Shai-Hulud" self-replicating npm worm, called the first npm supply-chain worm | supply | research/threats/incidents/supply-shai-hulud-worm.md | https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack |
| INC-004 | 2025-09 | chalk and debug npm packages compromised, malicious code shipped to millions | supply | research/threats/incidents/supply-chalk-debug-compromise.md | https://github.com/debug-js/debug/issues/1000 |
| INC-005 | 2025-07 | Amazon Q developer agent compromised via a crafted pull request on GitHub | supply | research/threats/incidents/supply-amazon-q-pr-hijack.md | https://www.lasso.security/blog/amazon-q-ai-agent-hijack-attempt |
| INC-006 | 2025-11 | Malicious postmark-mcp MCP server blind-copied user emails to the attacker | mcp | research/threats/incidents/mcp-postmark-mcp-backdoor.md | https://www.koi.ai/blog/postmark-mcp-malicious-package-backdoor |
| INC-007 | 2025-08 | Gemini CLI tricked by a malicious GitHub issue into exfiltrating data (PoC) | inject | research/threats/incidents/inject-gemini-cli-issue-exfil.md | https://tracebit.com/blog/gemini-cli-data-exfiltration-poc |
| INC-008 | 2025-04 | Cursor "rules file backdoor": persistent instruction injection through rules files | inject | research/threats/incidents/inject-cursor-rules-backdoor.md | https://www.hiddenlayer.com/novusbullentine/2025/cursor-rules-file-backdoor |
| INC-009 | 2026-02 | Codex cleanup session deleted 10+ directories beyond the approved scope (~328K files) | fs | research/threats/incidents/fs-codex-cleanup-blast-radius.md | https://github.com/openai/codex/issues/12277 |
| INC-010 | 2026-03 | Codex App on Windows deleted ~370 GB across the user's home, far outside the project folder | fs | research/threats/incidents/fs-codex-app-windows-outside-project.md | https://community.openai.com/t/critical-data-loss-issue-in-codex-app-for-windows-agent-executed-file-deletion-outside-project-directory/1375894 |
| INC-011 | 2026-03 | Second Claude Code instance reset the main worktree and destroyed another session's staged work | vcs | research/threats/incidents/vcs-claude-code-reset-hard-main-worktree.md | https://github.com/anthropics/claude-code/issues/33850 |
| INC-012 | 2026-06 | Poisoned take-home coding test turned a Cursor agent into a credential harvester in under two minutes | secrets | research/threats/incidents/secrets-take-home-test-agent-harvest.md | https://www.mitiga.io/blog/poisoned-coding-test-ai-agent-attack |
| INC-013 | 2025-05 | Prompt injection turned image rendering and auto-fetch tools into 0-click secret egress in Cline, Windsurf and Amp Code | exfil | research/threats/incidents/exfil-agent-image-render-exfil.md | https://embracethered.com/blog/posts/2025/cline-vulnerable-to-data-exfiltration/ |
| INC-014 | 2025-07 | eslint-config-prettier compromise: a phished token shipped a DLL-dropping install script to 30M weekly installs | supply | research/threats/incidents/supply-eslint-prettier-dll-drop.md | https://www.endorlabs.com/learn/cve-2025-54313-eslint-config-prettier-compromise----high-severity-but-windows-only |
| INC-015 | 2026-08 | A WIF of fresh access: one GitHub issue prompt-injection chain reached GCP Editor on a Gemini CLI triage runner | inject | research/threats/incidents/inject-gemini-issue-wif-gcp.md | https://www.pillar.security/blog/a-wif-of-fresh-access-how-a-github-issue-on-gemini-cli-led-to-gcp-project-compromise |
| INC-016 | 2025-07 | Supabase MCP turned a support ticket into an SQL heist of integration tokens | mcp | research/threats/incidents/mcp-supabase-ticket-exfil.md | https://generalanalysis.com/blog/supabase-mcp-blog |
| INC-017 | 2026-05 | Claude Code deep-research workflow turned a rate limit into a 97-agent retry storm that burned 2M tokens | behavior | research/threats/incidents/behavior-claude-code-429-retry-storm.md | https://github.com/anthropics/claude-code/issues/64328 |
| INC-018 | 2026-06 | Claude Code background agents resurrected after repeated Stops and burned 160k tokens over 21 hours | behavior | research/threats/incidents/behavior-claude-code-background-agents-resurrect.md | https://github.com/anthropics/claude-code/issues/66339 |
| INC-019 | 2025-08 | RingReaper used Linux io_uring to do file and network work where EDR hooks cannot see it | evade | research/threats/incidents/evade-ringreaper-iouring-edr-evasion.md | https://www.picussecurity.com/resource/blog/ringreaper-linux-malware-edr-evasion-tactics-and-technical-analysis |
| INC-020 | 2022-06 | Symbiote loaded itself via LD_PRELOAD into every process — including the monitoring tools | evade | research/threats/incidents/evade-symbiote-ld-preload-rootkit.md | https://intezer.com/blog/new-linux-threat-symbiote |
| INC-021 | 2025-12 | Claude Code cleanup command with a stray ~/ wiped a Mac home directory | behavior | research/threats/incidents/behavior-claude-code-rm-tilde-mac-wipe.md | https://gigazine.net/gsc_news/en/20251216-claude-code-cli-mac-deleted/ |
| INC-022 | 2026-08 | Claude Code TaskStop left an orphaned rm -rf /c deleting for 20 minutes | behavior | research/threats/incidents/behavior-claude-code-taskstop-orphan-rm.md | https://github.com/anthropics/claude-code/issues/85200 |
| INC-023 | 2025-12 | Cursor Plan Mode agent deleted tracked files and killed processes despite "DO NOT RUN ANYTHING" | behavior | research/threats/incidents/behavior-cursor-plan-mode-pkill-despite-freeze.md | https://forum.cursor.com/t/catastrophic-damage-and-chaos-in-plan-mode/145523 |
| INC-024 | 2025-10 | Comment and Control: GitHub issue text hijacked AI agents in CI and drained the runners' secrets | cloud | research/threats/incidents/cloud-comment-and-control-ci-agents.md | https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/ |
| INC-025 | 2025-12 | Amazon's Kiro agent deleted and recreated a production AWS environment, causing a 13-hour Cost Explorer outage | cloud | research/threats/incidents/cloud-kiro-delete-and-recreate.md | https://www.ft.com/content/00c282de-ed14-4acd-a948-bc8d6bdb339d |
| INC-026 | 2026-04 | Cursor agent deleted PocketOS's production database and its backups with one Railway API call | cloud | research/threats/incidents/cloud-pocketos-railway-volume-delete.md | https://x.com/lifeof_jer/status/2048103471019434248 |
| INC-027 | 2026-03 | Vercel agent hallucinated a GitHub repo ID and deployed the third-party code to a customer project | cloud | research/threats/incidents/cloud-vercel-hallucinated-repo-deploy.md | https://x.com/rauchg/status/2028920268119523788 |
| INC-028 | 2026-03 | CastleRAT abused the trusted Deno developer runtime to run fileless malware | evade | research/threats/incidents/evade-castlerat-deno-runtime-lotl.md | https://www.threatdown.com/blog/castlerat-cyber-attack-is-the-first-to-abuse-deno-javascript-runtime-to-evade-enterprise-security/ |
| INC-029 | 2025-04 | ANSI terminal escape codes hid attacker instructions from Claude Code users | evade | research/threats/incidents/evade-claude-code-ansi-hidden-payload.md | https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/ |
| INC-030 | 2022-08 | PyPI package 'secretslib' dropped a fileless Monero miner with memfd_create | evade | research/threats/incidents/evade-pypi-secretslib-fileless-miner.md | https://www.sonatype.com/blog/pypi-package-secretslib-drops-fileless-linux-malware-to-mine-monero |
| INC-031 | 2021-04 | Codecov bash uploader exfiltrated CI environment variables to an attacker server | exfil | research/threats/incidents/exfil-codecov-uploader-exfil.md | https://about.codecov.io/apr-2021-post-mortem/ |
| INC-032 | 2025-09-05 | GhostAction workflows POSTed CI secrets straight to an attacker HTTP endpoint | exfil | research/threats/incidents/exfil-ghostaction-workflow-exfil.md | https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/ |
| INC-033 | 2025-10 | GlassWorm hid in Open VSX extensions and moved stolen credentials over blockchain-driven egress | exfil | research/threats/incidents/exfil-glassworm-openvsx.md | https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace |
| INC-034 | 2025-11-23 | Shai-Hulud "Second Coming" wave bulk-uploaded harvested secrets to public GitHub repos | exfil | research/threats/incidents/exfil-shai-hulud-second-coming.md | https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised |
| INC-035 | 2025-11 | Google Antigravity agent wiped a whole drive partition during a cache cleanup | fs | research/threats/incidents/fs-antigravity-drive-wipe.md | https://www.theregister.com/software/2025/12/01/googles_vibe_coding_platform_deletes_entire_drive/1817705 |
| INC-036 | 2025-07 | Gemini CLI file-organizing session deleted the user's files | fs | research/threats/incidents/fs-gemini-cli-move-deletion.md | https://github.com/google-gemini/gemini-cli/issues/4586 |
| INC-037 | 2025-06 | Prompt injection in a source file made Claude Code leak .env through ping DNS requests | inject | research/threats/incidents/inject-claude-code-dns-ping-exfil.md | https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/ |
| INC-038 | 2025-08 | CurXecute: one prompt injection in Cursor rewrote the MCP config and ran attacker code | inject | research/threats/incidents/inject-cursor-curxecute-mcp-rce.md | https://www.aim.security/lp/aim-labs-curxecute-blogpost |
| INC-039 | 2026-06 | Agentjacking: a fake Sentry error became a shell command for coding agents | inject | research/threats/incidents/inject-sentry-mcp-agentjacking.md | https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/ |
| INC-040 | 2026-02 | ClawHavoc poisoned an agent skill marketplace with stealer payloads behind fake "prerequisites" | mcp | research/threats/incidents/mcp-clawhavoc-skills.md | https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting |
| INC-041 | 2025-05 | GitHub MCP server turned a malicious issue in a public repo into a private-repo data leak | mcp | research/threats/incidents/mcp-github-issue-pr-leak.md | https://invariantlabs.ai/blog/mcp-github-vulnerability |
| INC-042 | 2025-07 | mcp-remote ran OS commands from a hostile remote MCP server during the OAuth flow (CVE-2025-6514) | mcp | research/threats/incidents/mcp-remote-untrusted-server-rce.md | https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/ |
| INC-043 | 2026-08 | Black Hat 2026: one GitHub issue pulled CI secrets out of Claude Code, Gemini CLI and Codex | secrets | research/threats/incidents/secrets-novee-agent-ci-secrets.md | https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-cicd-secrets-20260808-csa/ |
| INC-044 | 2026-03 | Team PCP harvested 78,330 CI/CD secrets from 2,186 organizations through poisoned Trivy and LiteLLM builds | secrets | research/threats/incidents/secrets-team-pcp-cicd-harvest.md | https://www.cloudsek.com/blog/ai-supply-chain-breach-2500-companies-434000-cicd-pipelines |
| INC-045 | 2024-12-03 | Backdoored @solana/web3.js npm release exfiltrated private keys through the app's own process | supply | research/threats/incidents/supply-solana-web3js-backdoor.md | https://github.com/solana-labs/solana-web3.js/security/advisories/GHSA-jcxm-7wvp-g6p5 |
| INC-046 | 2025-03-14 | Compromised tj-actions/changed-files GitHub Action dumped CI secrets into public build logs | supply | research/threats/incidents/supply-tj-actions-changed-files.md | https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised |
| INC-047 | 2024-12-04 | Ultralytics PyPI releases shipped a cryptominer after CI workflow injection and token theft | supply | research/threats/incidents/supply-ultralytics-cryptominer.md | https://www.hiddenlayer.com/research/ultralytics-python-package-compromise-deploys-cryptominer |
| INC-048 | 2024-02/03 | xz Utils backdoor ran attacker code from a build script during compilation | supply | research/threats/incidents/supply-xz-build-backdoor.md | https://www.openwall.com/lists/oss-security/2024/03/29/4 |
| INC-049 | 2026-02 | Claude Code wiped uncommitted work with a path git checkout | vcs | research/threats/incidents/vcs-claude-code-checkout-uncommitted.md | https://erickhun.com/posts/when-your-ai-coding-assistant-destroys-your-work/ |
| INC-050 | 2025-12 | Codex agent ran git restore against an explicit "never touch git" instruction | vcs | research/threats/incidents/vcs-codex-restore-despite-ban.md | https://github.com/openai/codex/issues/8643 |
| INC-051 | 2026-01 | Cursor agent force-pushed with --no-verify despite explicit permission rules | vcs | research/threats/incidents/vcs-cursor-force-push-no-verify.md | https://news.ycombinator.com/item?id=46728766 |
| INC-052 | 2026-07 | Cursor subagents corrupted a dirty worktree and "recovered" with destructive git | vcs | research/threats/incidents/vcs-cursor-subagent-dirty-worktree.md | https://forum.cursor.com/t/agent-parallel-subagents-overwrite-dirty-worktree-destructive-git-recovery-wastes-tokens/166666 |

Rows with report `missing` still need a full incident report in `incidents/`.
Research runs verify the seeds (date, facts, source) and write the reports.

## Scenario ledger

| id | title | category | pack | decision | sev | coverage | status | sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SC-001 | Unquoted or empty variable in a recursive delete | filesystem | filesystem | approval_required | 5 | gap | proposed | INC-009 |
| SC-002 | Recursive delete of any path outside the session work tree | filesystem | filesystem | approval_required | 4 | partial | proposed | INC-009, INC-010 |
| SC-003 | Wipe of the user's data directories under home | filesystem | filesystem | deny | 5 | gap | proposed | INC-010 |
| SC-004 | Recursive delete of the work tree itself | filesystem | filesystem | approval_required | 4 | gap | proposed | - |
| SC-005 | Mass deletion without rm: find -delete, xargs, rsync --delete | filesystem | filesystem | approval_required | 4 | gap | proposed | INC-009 |
| SC-006 | Destructive move: wildcard or multi-source onto a non-directory | filesystem | filesystem | approval_required | 4 | gap | proposed | - |
| SC-007 | Deletion through interpreter APIs instead of a delete command | filesystem | filesystem | approval_required | 4 | gap | proposed | INC-009 |
| SC-008 | Delete burst or runaway recursive delete | process | cross | terminate | 5 | gap | proposed | INC-009 |
| SC-009 | In-place truncation or whole-file overwrite of data files | filesystem | filesystem | approval_required | 3 | partial | proposed | - |
| SC-010 | Clobbering shell startup files and top-level dotfiles | filesystem | filesystem | approval_required | 4 | gap | proposed | INC-002 |
| SC-011 | Recursive chown or chmod against system or home trees | filesystem | filesystem | approval_required | 4 | partial | proposed | - |
| SC-012 | Deletion through a symlink created earlier in the session | filesystem | filesystem | approval_required | 4 | gap | proposed | - |
| SC-013 | Collateral damage to sibling projects: node_modules, build output of other work trees | filesystem | filesystem | approval_required | 3 | partial | proposed | - |
| SC-014 | Package-manager or build-tool lifecycle deletion escaping the work tree | supply-chain | cross | approval_required | 4 | partial | proposed | - |
| SC-015 | Deletion of database files and backup files | database | database | approval_required | 4 | gap | proposed | - |
| SC-016 | Force-with-lease push combined with --no-verify | git | git | approval_required | 4 | partial | proposed | - |
| SC-017 | Hook bypass flag on commit or push | git | git | approval_required | 3 | gap | proposed | - |
| SC-018 | Hook tampering: writing .git/hooks/* or core.hooksPath | git | cross | approval_required | 4 | gap | proposed | - |
| SC-019 | Tree discard with explicit pathspecs (restore <path>, checkout <path>) | git | git | approval_required | 4 | partial | proposed | - |
| SC-020 | Discard-class command against a tree another live session wrote (cross-agent escalation) | agent-behavior | cross | deny | 5 | gap | proposed | INC-011 |
| SC-021 | Staging credential-bearing files into the index | secrets | cross | approval_required | 5 | gap | proposed | - |
| SC-022 | Push or remote write to a host that is not the session origin | git | cross | approval_required | 4 | gap | proposed | - |
| SC-023 | Credential material embedded in a remote URL | secrets | cross | deny | 5 | gap | proposed | - |
| SC-024 | Signing and identity tampering | git | git | approval_required | 3 | partial | proposed | - |
| SC-025 | Direct .git surgery by non-git processes | filesystem | cross | deny | 5 | partial | proposed | - |
| SC-026 | History and ref rewrite toolkit beyond the covered forms | git | git | approval_required | 3 | partial | proposed | - |
| SC-027 | Whole-repository export to a single file | exfil | cross | approval_required | 4 | gap | proposed | - |
| SC-028 | GitHub CLI destructive operations | cloud | cross | deny | 5 | gap | proposed | - |
| SC-029 | Unsolicited stash push / reset by the agent (state laundering) | agent-behavior | git | approval_required | 2 | gap | proposed | - |
| SC-030 | Forced worktree removal | git | git | approval_required | 3 | gap | proposed | INC-011 |
| SC-031 | Secrets in env files read outside the work tree | secrets | filesystem | approval_required | 3 | gap | proposed | INC-012 |
| SC-032 | CLI and agent credential vaults read | secrets | filesystem | approval_required | 4 | gap | proposed | INC-012 |
| SC-033 | Browser credential stores read | secrets | filesystem | approval_required | 4 | gap | proposed | - |
| SC-034 | Read of another process's environment or memory | secrets | process | deny | 5 | gap | proposed | - |
| SC-035 | Environment variables dumped through commands | secrets | process | approval_required | 3 | gap | proposed | - |
| SC-036 | Secret scanner executed from install-script or temp ancestry | secrets | process | deny | 5 | gap | proposed | - |
| SC-037 | grep or find sweep for secrets outside the work tree | secrets | process | approval_required | 4 | gap | proposed | INC-012 |
| SC-038 | Credential file fan-out in one session | secrets | cross | approval_required | 4 | gap | proposed | INC-012 |
| SC-039 | Token-shaped strings posted to third parties | secrets | network | approval_required | 4 | gap | proposed | - |
| SC-040 | Cloud secret manager and cluster secret reads | secrets | cloud | approval_required | 3 | gap | proposed | INC-012 |
| SC-041 | Archive staging of credential directories | secrets | process | approval_required | 4 | gap | proposed | - |
| SC-042 | Env and secret dumps POSTed out with curl or wget | secrets | network | deny | 5 | gap | proposed | - |
| SC-043 | Command output piped into a network tool's stdin | network | network | approval_required | 4 | gap | proposed | - |
| SC-044 | DNS lookups that carry stolen data in the name | network | network | approval_required | 4 | gap | proposed | - |
| SC-045 | Access to cloud instance metadata endpoints | cloud | network | deny | 5 | gap | proposed | - |
| SC-046 | Container runtime socket and local admin surfaces | network | cross | approval_required | 4 | gap | proposed | - |
| SC-047 | Uploads to paste sites, file drops and webhook collectors | network | network | approval_required | 4 | gap | proposed | - |
| SC-048 | Reverse tunnels that expose the machine | network | network | approval_required | 4 | gap | proposed | - |
| SC-049 | Bulk copy to an external host with scp, rsync or sftp | network | network | approval_required | 4 | gap | proposed | - |
| SC-050 | Credential file read followed by external egress | secrets | cross | deny | 5 | gap | proposed | INC-012, INC-013 |
| SC-051 | Egress to raw IP addresses with no DNS name | network | network | approval_required | 3 | gap | proposed | - |
| SC-052 | Package manager lifecycle egress outside the registry allowlist | supply-chain | cross | approval_required | 4 | gap | proposed | - |
| SC-053 | Cloud CLI uploads to buckets the project never uses | cloud | cloud | approval_required | 4 | gap | proposed | - |
| SC-054 | Secrets smuggled in URLs and image fetches | network | network | approval_required | 4 | gap | proposed | INC-013 |
| SC-055 | Downloaded script that makes its own egress | process | cross | approval_required | 4 | partial | proposed | - |
| SC-056 | Install lifecycle hooks spawning child processes | supply-chain | cross | approval_required | 4 | gap | proposed | INC-002, INC-003, INC-014 |
| SC-057 | AI coding CLI launched by a non-agent parent with permission-bypass flags | supply-chain | cross | terminate | 5 | gap | proposed | INC-002 |
| SC-058 | Credential-enumeration prompt or script text visible in argv | supply-chain | cross | deny | 5 | gap | proposed | INC-002 |
| SC-059 | Ad-hoc package installs outside the project's dependency graph | supply-chain | process | approval_required | 4 | gap | proposed | - |
| SC-060 | Install sources overridden to git URLs, tarballs or custom registries | supply-chain | process | approval_required | 4 | gap | proposed | - |
| SC-061 | Known-malicious package versions at the install gate | supply-chain | process | deny | 4 | gap | proposed | INC-002, INC-003, INC-004, INC-014 |
| SC-062 | CI workflow files written during a dev session | supply-chain | git | approval_required | 4 | gap | proposed | - |
| SC-063 | First execution of binaries freshly written by a package install | supply-chain | cross | allow | 3 | gap | proposed | INC-002, INC-003 |
| SC-064 | Publishing operations from an interactive session | supply-chain | process | approval_required | 4 | gap | proposed | INC-002, INC-003 |
| SC-065 | Drop-then-execute from an install hook (file write, then run) | supply-chain | cross | approval_required | 4 | partial | proposed | INC-003, INC-014 |
| SC-066 | Installer execution following freshly fetched instructions | prompt-injection | cross | approval_required | 3 | gap | proposed | - |
| SC-067 | Build tools executing non-toolchain children | supply-chain | process | allow | 2 | partial | proposed | - |
| SC-068 | Agent instruction and rules files written from agent ancestry | prompt-injection | filesystem | approval_required | 4 | gap | proposed | INC-008 |
| SC-069 | Agent rewrites its own permission, hook or MCP configuration | prompt-injection | filesystem | deny | 5 | gap | proposed | INC-015 |
| SC-070 | Executable dropped into a PATH directory (shadowing the next tool call) | process | process | approval_required | 4 | gap | proposed | - |
| SC-071 | Agent launches another agent (or itself) with autonomous flags | agent-behavior | process | deny | 4 | gap | proposed | INC-015, INC-017, INC-018 |
| SC-072 | Compound command rides a session-approved prefix | prompt-injection | process | approval_required | 4 | gap | proposed | INC-007 |
| SC-073 | Whitespace, control-character or homoglyph obfuscation inside a command line | evasion | process | approval_required | 3 | gap | proposed | INC-007 |
| SC-074 | Invisible Unicode written into repo or instruction files | prompt-injection | filesystem | approval_required | 3 | partial | proposed | INC-008 |
| SC-075 | Session taint: untrusted document read precedes the first risky action | prompt-injection | cross | approval_required | 4 | gap | proposed | INC-007 |
| SC-076 | Durable data drops into GitHub issues, PRs and releases | prompt-injection | network | approval_required | 4 | gap | proposed | INC-015 |
| SC-077 | CI OIDC and WIF credential files read | secrets | filesystem | deny | 5 | partial | proposed | INC-015 |
| SC-078 | Agent session logs wiped or CI runner kept alive | agent-behavior | process | approval_required | 3 | gap | proposed | INC-007, INC-015 |
| SC-079 | Cloud token minting and service-account impersonation from agent ancestry | cloud | cloud | approval_required | 5 | gap | proposed | INC-015 |
| SC-080 | Ignore files edited to steer or blind the agent | prompt-injection | filesystem | approval_required | 3 | gap | proposed | INC-012, INC-015 |
| SC-081 | Destructive operations through PaaS CLI tools | cloud | cloud | approval_required | 4 | gap | proposed | INC-001 |
| SC-082 | Migration tools that reset or roll back a real database | database | database | approval_required | 4 | gap | proposed | INC-001 |
| SC-083 | Write-grade SQL when the connection points at production | database | database | approval_required | 5 | partial | proposed | INC-001 |
| SC-084 | kubectl exec, cp and port-forward against production workloads | cloud | cloud | approval_required | 4 | gap | proposed | - |
| SC-085 | First contact: mutating verbs against a non-local cluster with no production in the name | cloud | cloud | approval_required | 4 | partial | proposed | - |
| SC-086 | Terraform destroy by other name: replace, taint, and state tampering | cloud | cloud | approval_required | 4 | gap | proposed | - |
| SC-087 | Production deployments from agent ancestry | cloud | cloud | approval_required | 4 | gap | proposed | - |
| SC-088 | gh CLI operations on CI secrets and workflow runs | secrets | cloud | approval_required | 4 | gap | proposed | - |
| SC-089 | Destructive mutations sent by generic HTTP clients to cloud control planes | network | network | approval_required | 5 | gap | proposed | - |
| SC-090 | DNS and domain record changes from agent ancestry | cloud | cloud | approval_required | 4 | gap | proposed | - |
| SC-091 | Capacity and cost amplification | cloud | cloud | approval_required | 3 | partial | proposed | - |
| SC-092 | Delete-and-recreate of an environment without a plan artifact | agent-behavior | cross | deny | 5 | gap | proposed | INC-001 |
| SC-093 | SSH port-forward that re-homes production onto localhost | evasion | network | approval_required | 4 | gap | proposed | - |
| SC-094 | First launch of an MCP server command the session has not seen | mcp | process | approval_required | 4 | gap | proposed | INC-006 |
| SC-095 | Shell or interpreter spawned under an MCP server | process | process | deny | 5 | gap | proposed | - |
| SC-096 | First outbound connection of a freshly started MCP server | network | network | approval_required | 4 | gap | proposed | INC-006 |
| SC-097 | MCP server package rewritten and relaunched in one session (rug pull) | supply-chain | cross | approval_required | 4 | gap | proposed | INC-006 |
| SC-098 | Write-shaped MCP tool calls on the stdio | mcp | cross | approval_required | 4 | gap | proposed | INC-016 |
| SC-099 | Read-then-write-back correlation across MCP tool calls | mcp | cross | approval_required | 5 | gap | proposed | INC-016 |
| SC-100 | dlx exec of a package outside the project manifests | supply-chain | process | approval_required | 3 | gap | proposed | INC-006 |
| SC-101 | MCP server launched with service or admin credentials | secrets | process | approval_required | 3 | gap | proposed | INC-006, INC-016 |
| SC-102 | Marketplace skill read followed by first-time external exec | mcp | cross | approval_required | 4 | partial | proposed | - |
| SC-103 | Extension host spawns interpreters from extension directories on load | supply-chain | process | approval_required | 4 | gap | proposed | - |
| SC-104 | First contact with a remote MCP endpoint | network | network | approval_required | 3 | gap | proposed | - |
| SC-105 | Mail and webhook tool calls with unexpected recipients | mcp | network | approval_required | 3 | partial | proposed | INC-006 |
| SC-106 | Duplicate MCP tool names across servers (shadowing) | mcp | mcp | approval_required | 3 | gap | proposed | - |
| SC-107 | MCP file server reads outside the work tree | filesystem | filesystem | approval_required | 3 | gap | proposed | INC-016 |
| SC-108 | Agent kills processes by broad pattern | process | process | approval_required | 4 | gap | proposed | - |
| SC-109 | Agent kills its own process tree, sibling sessions or the monitor | process | cross | terminate | 5 | gap | proposed | - |
| SC-110 | Detached daemons and background jobs that outlive the session | process | process | approval_required | 4 | gap | proposed | INC-018 |
| SC-111 | Runaway retry loop or fan-out burning API quota | agent-behavior | cross | terminate | 4 | gap | proposed | INC-017 |
| SC-112 | Agent manages its own installation: self-update and reinstall | agent-behavior | cross | approval_required | 3 | gap | proposed | - |
| SC-113 | Agent disables or uninstalls security tooling | agent-behavior | cross | deny | 5 | gap | proposed | - |
| SC-114 | Agent schedules work to run after the session ends | agent-behavior | process | approval_required | 3 | partial | proposed | - |
| SC-115 | Wrong-target edits outside the session work tree | agent-behavior | filesystem | approval_required | 4 | partial | proposed | INC-010 |
| SC-116 | Failed-command retry escalation: re-running with the bypass added | agent-behavior | cross | approval_required | 4 | gap | proposed | - |
| SC-117 | Operations reach a second remote host the session was not scoped to | agent-behavior | network | approval_required | 4 | gap | proposed | - |
| SC-118 | Agent rewrites or destroys its own session state and transcripts | agent-behavior | cross | approval_required | 3 | partial | proposed | - |
| SC-119 | Dangerous shell builtins that never exec | evasion | process | approval_required | 4 | gap | proposed | - |
| SC-120 | Process-name masquerading: exec -a and tool-name copies | evasion | process | approval_required | 3 | gap | proposed | - |
| SC-121 | Interpreter one-liners as generic file and network proxies | evasion | process | approval_required | 3 | partial | proposed | - |
| SC-122 | Fileless execution via memfd_create and /proc/self/fd | evasion | process | approval_required | 4 | gap | proposed | - |
| SC-123 | Write-then-chmod-then-exec payload assembly in-session | evasion | process | approval_required | 4 | partial | proposed | - |
| SC-124 | Loader-environment injection: LD_PRELOAD, LD_AUDIT, /etc/ld.so.preload | evasion | process | approval_required | 4 | gap | proposed | INC-020 |
| SC-125 | Attack on the monitor itself: signals, stop, sysctl, self-trace | evasion | cross | terminate | 5 | gap | proposed | - |
| SC-126 | Ancestry escape: setsid, nohup, double fork, reparenting | evasion | process | approval_required | 4 | gap | proposed | - |
| SC-127 | Encoded payload variants beyond base64 | evasion | process | approval_required | 3 | partial | proposed | - |
| SC-128 | Archive and pipe smuggling into PATH and system directories | evasion | cross | approval_required | 4 | gap | proposed | - |
| SC-129 | Namespace, mount, and chroot shadowing | evasion | process | approval_required | 4 | gap | proposed | - |
| SC-130 | Hardlink and symlink relabeling of credential and system files | evasion | cross | approval_required | 4 | gap | proposed | - |
| SC-131 | Approval-time versus action-time file identity (TOCTOU) | evasion | process | approval_required | 3 | gap | proposed | - |
| SC-132 | io_uring batch I/O invisible to per-syscall observation | evasion | cross | deny | 4 | gap | proposed | INC-019 |

## Run log

| date | incidents added | scenarios added | duplicates merged | notes |
| --- | --- | --- | --- | --- |
| 2026-08-28 | 12 | 132 | 15 | failed axes: none |
| 2026-08-28 | 32 | 0 | 5 | backfill: ledger rows for the 37 reports of research run 1; 5 cross-axis duplicate reports share a row with their primary |
