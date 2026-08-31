# Agent identity: detection, propagation, escape — measured

Spike home: `research/detection/` (`[af-3]`, milestone M3, workstreams W3 and
W4 of `docs/DIRECTION.md` §11). Machine: Fedora 43, kernel 7.0.9, `x86_64`,
uid 1000, no root, `yama/ptrace_scope = 0`. The detectors themselves ship in
`af-core::identity`; this directory holds the gate measurements. Re-run
everything with `./run.sh` (about 2 minutes, release build required).

## Verdict

The gate passed on all three measurements:

1. **Detection is measured and precise.** On a fixture corpus of 23 agent and
   30 non-agent commands: **precision 1.000** (22 of 23 agent fixtures tagged,
   0 of 30 non-agent fixtures tagged), **recall 0.957**. The one miss is
   deliberate and honest: the bare, ambiguous program name `pi` carries a
   supporting weight only (0.60), because other software also answers to that
   name; it tags together with any second signal. A false agent tag is worse
   than no tag, so every tie goes to quiet.
2. **Identity holds through the tree, and events carry it.** A session whose
   root the detectors tag (`CLAUDECODE=1` on a shell running a plain C
   fixture) stamps the tag on every event — 11 of 11 in the escape run — and
   the tag follows the graph, not the program names.
3. **A fixture escape is flagged.** The `escape-setsid` fixture (setsid +
   double fork + re-exec, `evade-08`) produced exactly two `process_unlinked`
   events under the product — the middle process that called `setsid`,
   flagged at its own exit, and the leaf that inherited the new session,
   flagged at its re-exec — each with the measured session identifiers
   (`sid 1322935` vs `root_sid 1322934`). The flagged leaf **kept its agent
   tag** (`claude-code`, `link: unlinked`) and its ancestry to the root —
   unlinked, never foreign. Without an agent tag the same escape is still
   flagged: the flag is a liveness fact of the tree, not a property of the
   identity. The `outlive` daemon of `behavior-03` — which calls `setsid` and
   never runs another program — is flagged at its exit event (`sid 1322967`
   vs `root_sid 1322463`); the exit event carries the session identifier for
   exactly that case.
4. **Quiet holds.** The benign corpus ran with **zero questions and zero
   agent tags** in all three filter modes (`research/bypass/benign.sh`, which
   now counts tags in its PASS criteria). The ambient environment of the
   measurement machine carries a lone agent marker (`PI_CODING_AGENT`, set by
   the harness this run was executed from); at its supporting weight of 0.70
   it stays below the tagging line, which is the quiet rule working, not a
   scrubbed environment.

## What shipped

| piece | where | what it is |
| --- | --- | --- |
| detector interface | `af-core::identity` | `Detector` trait (facts in, weighted signals out), `DetectorRegistry` (noisy-OR over detectors, tag at ≥ 0.75), plugin-shaped: `register(Box<dyn Detector>)` |
| known executables | `af-core::identity` | name table with per-agent weights (`claude` 0.95 … `pi` 0.60) |
| argv patterns | `af-core::identity` | runners (`npx`, `bunx`, `uvx`, `pnpm dlx`, `uv tool run`) naming an agent package; interpreters (`node`, `bun`, `deno`, `tsx`, `python -m`) carrying an agent install path or module |
| install layout | `af-core::identity` | package-manager metadata on the resolved executable path (`node_modules/@anthropic-ai/claude-code`, `.claude/local/claude`, `.opencode/bin/`, …) |
| dependency manifests | `af-core::identity` | `package.json` dependency names of the working directory — a supporting signal at 0.35 that can never tag alone (a repo that develops *with* an agent depends on its package) |
| characteristic env | `af-core::identity` | `CLAUDECODE=1` (0.90, exact value), `CLAUDE_CODE_ENTRYPOINT` / `PI_CODING_AGENT` (0.70, presence). An API key is never a marker; `CLAUDECODE=0` is not a marker |
| session fact | `af-core::session` | `SessionMeta.detection` carries name, confidence and every signal inside the `SessionStart` event; a replay reads the identity from the trace and never detects again |
| event fact | `af-core::event` | `Event.agent: Option<AgentTag>` (name, confidence, `linked`/`unlinked`); stamped by the launcher's handler on every event of a tagged session |
| launcher wiring | `af-cli::run` | assessment at launch (PATH-resolved program, command line, inherited env, manifests); one stderr line when a tag lands, silence otherwise |
| escape flag | `af-core` + `af-provenance` + `af-monitor` | `ProcessInfo.sid` from `/proc/<pid>/stat`, read at the exec stop and at the exit stop; the graph compares every process's session id with the root's, flags a differing descendant `process_unlinked` with `SessionDetach { sid, root_sid }`, and never drops ancestry or identity |
| corpus | `crates/af-core/tests/identity_corpus.rs` | 53 fixtures, computes precision/recall, asserts precision 1.0 and recall ≥ 0.9 |

## The signal table, measured

| detector | strongest weight | tags alone | corpus contribution |
| --- | --- | --- | --- |
| known executables | 0.95 (0.60 for `pi`) | yes (not `pi`) | 6 fixtures |
| argv patterns | 0.90 | yes | 9 fixtures |
| install layout | 0.85 | yes | 1 fixture (reinforces 4 more) |
| characteristic env | 0.90 exact / 0.70 presence | exact only | 4 fixtures |
| dependency manifests | 0.35 | never | 0 positives; 1 negative kept quiet |

Combination is a noisy OR **over detectors**, not hits: one detector with
many matches contributes its best weight once, so a manifest naming five
agent packages still cannot tag a build (`npm test` in an agent-aware repo is
a measured negative). Two supporting signals cross the line together —
measured: `pi` + `PI_CODING_AGENT` tags; `pi` + nothing does not.

## Method and honesty

* **The corpus is synthetic.** No real coding agent is installed on this
  machine, and none may be. Every agent fixture reproduces a real arrival
  shape (bare executable, npm/pnpm/uv runner, interpreter running the
  installed package, agent-set environment markers) with the paths and marker
  values the agents document. The corpus is committed as runnable code and
  says its numbers in `cargo test -p af-core --test identity_corpus -- --nocapture`.
* **The escape runs are real.** The fixture binaries from `[af-1]` ran
  under the release build with `--retention all`; the classification reads
  the trace structurally and verifies the effect (the marker file) from the
  file system, never from the fixture's own stdout. `agent-firewall tree`
  and `agent-firewall replay` both read the trace with the new event kinds.
* **What detection does not do.** Detection runs once, at launch, from
  launcher facts. It does not watch a process the firewall did not start
  (attach mode stays the M3 follow-up of `docs/MILESTONES.md`), it keys on no
  path read from the memory of a judged program, and no rule anywhere allows
  an action because a detector spoke. The trace stop still follows the
  detached process — the flag reports detachment, it never claims the process
  went unseen.

## What feeds the next milestones

* **M4 (tamper and quarantine):** `process_unlinked` is the B.6 liveness fact
  the quarantine flow keys on, and `SessionDetach` carries the measured
  identifiers a rule can read. Both fixture shapes of `[af-1]` raise it
  today: the escape chain (`evade-08`) and the outlive daemon
  (`behavior-03`), measured above.
* **M5 (correlation):** events now carry agent identity, so a discrepancy
  report can name *which agent's* expected view failed.
* **The rule pack:** no shipped rule consumes identity yet; `subtree` and
  `session` scopes and the approval flow behave exactly as before. A rule
  that reads the tag is new rule work under the interruption budget
  (`docs/POLICY.md` §6), not part of this milestone.
