# Retro: Direction-of-record adoption, the milestone ladder, and three workflow-authoring rakes

**Date**: 2026-09-01
**Session**: 01a05464-27e7-7617-8cb4-22a4b426bdd1
**Transcript**: /home/vfeenstr/.pi/agent/sessions/--home-vfeenstr-devel-lab-opinicus-56sol--/2026-08-30T20-37-25-095Z_01a05464-27e7-7617-8cb4-22a4b426bdd1.jsonl
**Duration / tokens / cost**: 125,459 s (~34.8 h wall, includes two long background workflow runs) / input 2,845,654 + output 251,246 + cacheRead 41,406,464 = 44,503,364 tokens / $0.00 (zai/glm-5.3-flash). 24 user turns, 205 assistant messages, 220 tool calls, 0 compactions; stop reasons 182 toolUse / 18 stop / 4 aborted (all user aborts) / 1 error.
**Extraction**: /home/vfeenstr/devel/lab/opinicus-56sol/docs/retros/i-have-an-update-on.extract.json

## What happened

The user delivered a major direction update (cross-platform defense-in-depth security layer for AI agents) and asked the agent to adopt it as the direction of record. The agent wrote `docs/DIRECTION.md`, `docs/DECISIONS.md`, `AGENTS.md`, `research/README.md`, and reconciled six existing docs (commit `b7a0a9f`), then tightened two over-broad sections after a critique the user solicited (`c3ef8ca`). It turned the learning plan into `docs/MILESTONES.md` (M1–M7, `9efe07e`), created a rohrpost epic `[af]` with eight gate-tracked tickets, and executed M1 (the bypass harness) itself — discovering the `pydrop` gap (python3.14 symlink escapes the interpreter list) along the way. It then declared `glm-5.3` in the user's global `~/.pi/agent/models.json` and ran the remaining seven milestones as a sequential 7-agent workflow (~5.8 h), independently re-verifying every gate afterwards. Two more background workflows ran threat-research loops (main 10-axis loop; a Hugging Face deep-dive, relaunched once after a fat-prompt failure), plus an ad-hoc documentation audit (io_uring) and an evidence-erasure analysis — each verified against primary sources and committed. Three self-inflicted workflow incidents stand out: a placeholder-args launch that had to be killed, a fat-prompt synthesis failure the repo's own script comments warn about, and ~12 calls reverse-engineering the `rp` CLI although a full rohrpost SKILL.md was visible in a directory listing.

## What worked

- **Independent verification of subagent claims** (5ea977e2, af8ea786): after the 7/7 ladder self-reported success, the agent re-ran fmt/clippy/361 tests/e2e/benign corpus itself before reporting. Same discipline for research output: 3/3 source spot-checks for the main loop (de5340c3–f04a389b) and near-forensic verification of the HF deep-dive against primary posts (752b8bd8, 12f1d4f2).
- **The pydrop root-cause hunt** (eee0921a–2f0149c0): ~15 disciplined calls from symptom to mechanism (`/proc/pid/exe` resolves `python3` → `python3.14`, not in `INTERPRETERS`), ending in a decisive name-keyed contrast pair (held `python` copy vs silent `/usr/bin/python3`). This was the milestone's purpose, executed well.
- **Careful kill hygiene** (6633e776): before killing the bad workflow run, the agent identified its own pid by start time against other live sandbox processes, then verified zero stray writes and an intact ledger.
- **Catching the gitignore trap** (5633e686, c4f7363a): noticed the repo's deliberate `*.jsonl` rule was swallowing the rohrpost ticket store, compared with the user's other rohrpost repos, and fixed with scoped negations plus explanatory comments that survive in `.gitignore` today.

## Friction

- **Placeholder-args workflow launch** (0a9bc9e9, 9326440c, 5bb7f76e): the agent built the real dedup args into `/tmp/af1-wf-args.json`, then launched the workflow with literal `{"ledger":"PLACEHOLDER","knownReports":[]}`. It caught the mistake within a minute, killed the run (a1f9d64b, 6633e776), relaunched correctly (6067c3dd), and verified args post-launch (b457c54f) — but the user later received a scary "workflow failed — 0/4 agents" notification that needed explaining (556c7988, 6a9bb3fc, f3f23a47). Root cause chain: the skill (`.pi/skills/threat-research/SKILL.md` step 2) and the script header comment both mandate inlining the *full* LEDGER.md content into `args` — a heavyweight inline contract the model balked at and placeholder'd; the `ledger` arg is in fact dead code (assigned at `threat-research.workflow.js:40`, never read by any prompt); and no step verifies the launched args before the run gets going.
- **Fat-prompt synthesis failure** (f3115f29, aa266fca, d966b76b): the ad-hoc HF deep-dive workflow inlined three researchers' full findings JSON into the synthesis prompt and died with "invalid agent request" after the research phase had already succeeded (6m24s, 3 agents wasted). The agent itself noted it "stepped on the rake the script was already warning about" — the warning lives only in a comment inside `threat-research.workflow.js:28-29`, which the agent had read earlier in the session, and did not hold at the moment of authoring a *new* script. Root cause: workflow-authoring guidance exists only as a comment in one script; there is no rule where ad-hoc scripts get written.
- **Stale threat-layer context caught only by initiative** (a66cc5f7, 387e29d6, 671e5446, 8b6c49fb): before the research loop, the agent discovered the workflow CONTEXT block and LEDGER still described the *pre-ladder* monitor ("does not emit file_open/network_connect") and a false headline ("37% cannot be expressed") — researchers would have judged scenarios against a monitor that no longer exists. It refreshed both and passed `check.py` before launching (commit `0453a57`). Root cause: the skill's runbook has no context-freshness step, so correctness depended on the agent noticing.
- **rohrpost interface reverse-engineered; skill seen but not read** (12b3a5c4–a02efe26, 12 tool calls): the agent probed `--help`, read the event log, grepped package sources, and read the worthless venv shim `/home/vfeenstr/.local/bin/rp`. The listing it itself requested (result of 9a024c72) showed `playbooks scripts SKILL.md` in `~/devel/lab/skill-manager/.agents/skills/rohrpost/` — a full 182-line SKILL.md with the work loop, `--json` convention, and actor identity — and it still read the bin stub instead. This is "the affordance existed and was pointed at, but was not used". Root cause: no rohrpost skill is installed for this repo and AGENTS.md's rohrpost bullet does not point to one, so the discovery path led through raw exploration.
- **Cargo workspace auto-attach, two rounds, ~25 calls** (0ae118bd, 542d79ba, 2b90a82c, 0372e712, 2d6e335a, dd50c9b5): corpus crates built under `tmp/` kept joining the repo workspace; the first fix (`exclude = ["tmp"]` + `[workspace]` append) failed because `cargo new` auto-registers by walking up and rewrites the root manifest before either matters. The robust fix — build scratch crates in system `/tmp`, copy binaries in — was found on the second round when the crates re-attached during the check suite. Root cause: no repo-level rule warns against `cargo new` inside the tree; the knowledge now lives only in `research/bypass/FINDINGS.md:178`.
- **User-facing limits lists lagged the measurements** (b56371f9–7ad941a4): io_uring was documented in six research-layer places, but the two lists a user reads before trusting the tool (README "Does not work yet", ARCHITECTURE §4) lacked it until the user asked "we do have this documented, right?" — fixed in `93ee227`. Root cause: no rule ties a landed measurement/mechanism decision to the user-facing limits lists in the same change.

Minor, acknowledged without proposals: 4 edit-tool retries (overlap/mismatch: 13cd97ce, 7fb9dbbc, f7d69474, 63016152) and one `fd` regex slip (478b9b35), each recovered in one step; one 102 KB `cat` of an event log (result of 96 line, d43599c1) that could have been a `head -6`; the four user aborts (44af414c, 0b2ced67, c527fe1e, b351ca9d) were the user refining their own messages, not agent friction.

## Skill pass — `.pi/skills/threat-research/SKILL.md` (read at b123a698)

- **Wrong guidance (step 2 args contract)**: mandates `ledger: full current content of LEDGER.md`, but the script never reads that arg (line 40 assigns it; no prompt uses it). This is the direct ancestor of the PLACEHOLDER launch. Fix below.
- **Under-specification (launch verification)**: nothing tells the agent to confirm the launched run received the real args (the agent invented this step on relaunch, b457c54f) or how to kill a fresh run safely (derived at 6633e776).
- **Missing guidance (authoring variants)**: the skill covers "add or retire axes" but not authoring new workflow scripts — exactly where the fat-prompt failure happened, despite the warning in the referenced script's comments.
- **Missing guidance (context freshness)**: step 1 says "read LEDGER.md and the workflow script" but never says to check they still describe the current build; the pre-run refresh was the agent's own idea.
- Post-run protocol (check.py, spot-checks, follow-up report) matches what the agent did — no gap there.

## Recurrence pass

All five friction items would recur in the next session of this repo: every threat-research run re-reads the wrong args contract (1); any new background workflow risks the fat prompt (2); any run after a milestone ships risks stale CONTEXT (3); any ticket work re-derives the rp interface (4); any scratch crate re-triggers workspace auto-attach (5); any new measured gap re-lags the limits lists (6). The rohrpost snapshot rule in AGENTS.md (added 2026-09-01, post-session) already covers store integrity around workflows — not duplicated below. Chosen forms: the threat-research fixes belong in the skill the workflow already requires reading (form 2); the three repo-wide conventions are one pointer line each in AGENTS.md (form 1). No multi-agent orchestration is needed to fix any of these — they are failures of written contracts, not of parallelism.

## Proposals

| # | Type | Change | Where | Evidence | Status |
|---|------|--------|-------|----------|--------|
| 1 | skill-update | Fix the launch contract: drop the dead `ledger` full-content arg, forbid placeholder/empty `knownReports`, add post-launch args verification and safe-kill steps | `.pi/skills/threat-research/SKILL.md`, step 2–3 | 0a9bc9e9, 9326440c, 5bb7f76e, b457c54f, 6633e776; script line 40 | done (applied 2026-09-01, user approved) |
| 2 | doc-update | Align the script's header comment with its actual args contract (no `ledger` arg) and delete the dead `LEDGER` const | `research/threats/threat-research.workflow.js` header comment + line 40 | 9326440c vs. script line 40 (arg never read) | done (applied 2026-09-01, user approved) |
| 3 | skill-update | Add a workflow-authoring rule: inter-agent data travels via files on disk + `read`, never inline JSON ("fat prompt fails with `invalid agent request`") | `.pi/skills/threat-research/SKILL.md`, Rules section | f3115f29, aa266fca, d966b76b; script comment lines 28–29 | done (applied 2026-09-01, user approved) |
| 4 | skill-update | Add a pre-launch context-freshness check (CONTEXT block + ledger observable summary must match the currently built monitor) | `.pi/skills/threat-research/SKILL.md`, Rules section | a66cc5f7, 387e29d6, 8b6c49fb (commit 0453a57) | done (applied 2026-09-01, user approved) |
| 5 | rule-update | AGENTS.md: point rohrpost work at the rohrpost skill instead of CLI reverse-engineering | `AGENTS.md`, "Rules that matter", rohrpost bullet | 12b3a5c4–a02efe26 (12 calls); SKILL.md visible in result of 9a024c72, unread | done (applied 2026-09-01, user approved) |
| 6 | rule-update | AGENTS.md: never `cargo new` inside the repo tree; build scratch crates in `/tmp` and copy artifacts in | `AGENTS.md`, "Rules that matter" (new bullet) | 0ae118bd, 542d79ba, 0372e712, 2d6e335a, dd50c9b5 (~25 calls) | done (applied 2026-09-01, user approved) |
| 7 | rule-update | AGENTS.md: measured gaps and mechanism decisions must update README "Does not work yet" + ARCHITECTURE §4 in the same change | `AGENTS.md`, "Rules that matter" (new bullet) | b56371f9–7ad941a4 (user had to ask), commit 93ee227 | done (applied 2026-09-01, user approved) |

### Proposal details (actual text)

**1. `.pi/skills/threat-research/SKILL.md` — replace step 2 and insert a verification step 3** (renumber the rest):

```markdown
2. Call the `workflow` tool with:
   - `script`: the full content of `research/threats/threat-research.workflow.js`
   - `args`: JSON string `{"knownReports": [{"f": "<file>.md", "t": "<title>"}, ...]}`
     for every report already in `incidents/` (so nothing is researched twice).
     Researchers and the merge agent read `LEDGER.md` and the axis catalogs
     from disk; the script takes no `ledger` arg. Never launch with a
     placeholder or an empty `knownReports`.
   - `background: true`
3. Before announcing the run: read `~/.pi/agent/workflows/<wf-id>/` and confirm
   the parsed args carry the real `knownReports` count. To stop a fresh run,
   identify the runner pid in `ps` output first (other sandboxes may be live),
   kill only that pid, then confirm `git status research/threats/` is untouched.
```

**2. `research/threats/threat-research.workflow.js`** — header comment, replace:

```js
//   { "ledger": "<content of LEDGER.md>",
//     "knownReports": [{ "f": "<file>.md", "t": "<title>" }, ...] }
```

with:

```js
//   { "knownReports": [{ "f": "<file>.md", "t": "<title>" }, ...] }
// knownReports lists incident reports already on disk (do not redo them).
// There is no ledger arg: researchers and the merge agent read LEDGER.md
// from disk.
```

and delete the now-dead `const LEDGER = state.ledger ?? '(empty ledger: first run)'` (line 40).

**3. SKILL.md Rules section, append**:

```markdown
- When authoring or editing any workflow script (this one or an ad-hoc variant,
  e.g. a single-incident deep dive), agents hand data to later phases by
  writing files under the repo (e.g. `tmp/threats/`) and having the next agent
  `read` them. Never inline one agent's full findings JSON into another
  agent's prompt: a fat prompt fails with "invalid agent request" (the comment
  at the top of `threat-research.workflow.js` says the same).
```

**4. SKILL.md Rules section, append**:

```markdown
- Before launching a run, check that the script's CONTEXT block and the
  ledger's observable summary describe the monitor as currently built (event
  kinds, policy packs). If a milestone shipped since the last run, refresh
  both first and run `check.py` before the launch: researchers judge coverage
  against what you tell them the monitor can see.
```

**5. `AGENTS.md`, extend the rohrpost bullet** — after "…resolve with a `rp comment` + `rp close` that names the committed measurement." insert:

```markdown
  Drive `rp` through the rohrpost skill — read
  `~/devel/lab/skill-manager/.agents/skills/rohrpost/SKILL.md` before invoking
  `rp`; do not reverse-engineer the CLI from `--help` and the wrapper source.
```

**6. `AGENTS.md`, new bullet after the rohrpost bullets**:

```markdown
- Never run `cargo new` (or add crates) anywhere inside this repo tree,
  including `tmp/`: cargo discovers the enclosing workspace, auto-registers
  the new crate, and rewrites the root `Cargo.toml` — `exclude = ["tmp"]`
  does not prevent it. Build scratch crates in `/tmp` and copy artifacts in
  (see `research/bypass/FINDINGS.md`, benign-corpus note).
```

**7. `AGENTS.md`, new bullet in "Rules that matter"**:

```markdown
- When a measurement or mechanism decision lands, update the user-facing
  limits lists in the same change: `README.md` "Does not work yet" and
  `docs/ARCHITECTURE.md` §4. Research-layer records (FINDINGS, ledger) do not
  substitute for them.
```

## Questions for the user

- `glm-5.3` was added to the **global** `~/.pi/agent/models.json` (backup at `models.json.bak-af-ladder`) so the ladder could run. Keep it global, or scope it to this project only?
- The rohrpost SKILL.md lives repo-locally in `skill-manager` and is invisible to other repos. Should it be installed globally (via skm) so it triggers everywhere — making proposal 5 a fallback rather than the primary fix?

## Application note (2026-09-01)

All seven proposals applied after explicit user approval ("Apply all 7"). Proposal 6's
bullet was placed after the "Numbers in documents" bullet (both are repo-hygiene rules);
proposal 7 was folded into the "Numbers" bullet as its second sentence, since the two
rules govern the same edit. The two questions above remain open for the owner.
