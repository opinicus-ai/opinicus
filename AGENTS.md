# AGENTS.md

Orientation for coding agents working in this repository.

## Read first

1. **`docs/DIRECTION.md` — the direction of record** (adopted 2026-08-30).
   Where any other document conflicts with it, it wins.
2. `docs/DECISIONS.md` — the dated decision log; the newest entry wins.
3. `docs/ARCHITECTURE.md` — what is really built today (as built).
4. `PROJECT.md` — the idea, the principles, the plan.
5. `docs/MILESTONES.md` — the game plan: the milestone ladder, the exit
   gate of each step, the current status.

## Rules that matter

- Keep **as built** and **as directed** separate. `docs/ARCHITECTURE.md`
  sections 1–7 describe shipped behavior; `docs/DIRECTION.md` describes the
  target. Never describe a planned sensor (in-process instrumentation,
  correlation, quarantine, telemetry) as shipped, and never weaken an as-built
  claim to fit the direction.
- **A sensor is not a boundary.** In-process instrumentation (`LD_PRELOAD`,
  Windows hooks) provides semantic visibility only. Never design it as an
  enforcement mechanism, and never use a path read from target memory as the
  basis for an allow decision (`docs/DETECTION-RESEARCH.md` §2: 47.6% wrong).
- **Research agents never publish production detection rules.** Candidate
  rules need deterministic tests, benchmarks, and human approval
  (`docs/DIRECTION.md` §8).
- Rule changes obey the interruption budget (`docs/PRODUCT.md` §5) and carry
  tests in the rule file (`docs/POLICY.md` §6). Every rule change runs
  `cargo test -p af-policy`.
- Plan and track execution through `docs/MILESTONES.md`. A milestone is
  done when its exit-gate measurement is committed next to runnable code —
  not when the code compiles. The benign corpus of M1 is the quiet test for
  every milestone that can ask a question.
- Numbers in documents must come from a measurement with a source (a doc
  section, a test, or a spike under `research/` with runnable code).
- Threat research runs through `research/threats/README.md` (skill:
  `threat-research`). After a research run, `python3
  research/threats/check.py` must pass before committing.
- New research work goes where `research/README.md` says (spikes, bypass
  harness, detection prototype). Every spike keeps a `FINDINGS.md` with raw
  numbers and runnable code.

## Checks

After changes, run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Docs-only changes still get `cargo fmt --check` as the cheap sanity pass.
