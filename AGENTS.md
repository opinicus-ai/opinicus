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
- Work is ticketed in `.rohrpost` (the `rp` CLI) under epic `[af]`, one
  ticket per milestone with its exit gate in the body. `rp ready` shows the
  unblocked work; claim with `rp claim`, resolve with a `rp comment` +
  `rp close` that names the committed measurement. Tickets live committed:
  a ticket that exists only in the working tree does not exist. Drive `rp`
  through the rohrpost skill — read
  `~/devel/lab/skill-manager/.agents/skills/rohrpost/SKILL.md` before
  invoking `rp`; do not reverse-engineer the CLI from `--help` and the
  wrapper source.
- **Snapshot the Rohrpost store around agent workflows.** Before any agent
  workflow runs against this repository, run `scripts/rohrpost-snapshot.sh`
  (records the commit, the store's git status and the sha256 of
  `.rohrpost/log.jsonl` and `.rohrpost/tickets.jsonl`). After a workflow
  that was supposed to be read-only, `scripts/rohrpost-snapshot.sh --check`
  must exit zero; a workflow that legitimately changes tickets commits the
  store and takes a fresh snapshot. Read-only means byte-identical
  (docs/DECISIONS.md, 2026-09-01).
- Multi-agent workflow runs follow `.pi/skills/agent-workflows/SKILL.md`:
  commit the script under `research/workflows/`, smoke-test helper-built
  agents, close phases on repo evidence (never agent self-report), and
  commit at every phase boundary.
- **Agents never write host-global or one-way kernel state on this machine.**
  Sysctls like `kernel.yama.ptrace_scope` are one-way per boot; a workflow
  agent that raised it latched this host until reboot (2026-09-01).
  Measurements that need kernel-global changes run in a disposable VM
  (`/dev/kvm` is available) or in CI. If shared host state is found mutated,
  surface it to the user immediately.
- Numbers in documents must come from a measurement with a source (a doc
  section, a test, or a spike under `research/` with runnable code). When a
  measurement or mechanism decision lands, update the user-facing limits
  lists in the same change: `README.md` "Does not work yet" and
  `docs/ARCHITECTURE.md` §4. Research-layer records (FINDINGS, ledger) do
  not substitute for them.
- Never run `cargo new` (or add crates) anywhere inside this repo tree,
  including `tmp/`: cargo discovers the enclosing workspace, auto-registers
  the new crate, and rewrites the root `Cargo.toml` — `exclude = ["tmp"]`
  does not prevent it. Build scratch crates in `/tmp` and copy artifacts in
  (see `research/bypass/FINDINGS.md`, benign-corpus note).
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
