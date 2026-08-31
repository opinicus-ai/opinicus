# Agent Firewall — The Definitive Project Review

**Date:** 2026-09-01 · **Repository:** `/home/vfeenstr/devel/lab/opinicus-56sol` · **HEAD reviewed:** `c7ca6f0` (`main`, clean tree, 57 commits, 2026-08-28 → 2026-08-31, single human author, all commits unsigned)
**Evidence base:** 12 first-pass agent transcripts (`wf_31658243be66/transcripts.json`), eight stage-2 review files (adversarial technical falsification, product falsification, trust/UX/commercial, verification, coverage cross-check, market cross-check, positive thesis, remediation plan) under `/tmp/agent-firewall-review-stage2`, and direct re-verification of every load-bearing claim against the repository by this reviewer (commands in §2).
**Standing instruction honored:** `docs/DIRECTION.md` is treated as direction of record; the newest `docs/DECISIONS.md` entries as binding; `docs/ARCHITECTURE.md` §§1–7 as as-built; `docs/MILESTONES.md` as the measured ladder. **M1–M7 `done` proves gates were passed and recorded at commit time — it does not prove production security, product-market fit, or that the gates are green today.** Two gates re-run during this review are in fact red or partially red (§2.3, §13).

---

## 1. Executive verdict

**Verdict: CONDITIONAL — a genuinely excellent, unusually honest Linux research alpha whose central product claims outrun its evidence. Viable as an observability/guardrail layer for cooperative or accidental coding agents. Not a security boundary against a hostile same-user process, on this or any evidence in the repository. No identified paying customer for the current laptop-shaped interactive product. One narrow commercial wedge is supported by the evidence — deterministic guardrails plus evidence-grade audit for unattended agents (CI, background/overnight, fleet VMs) holding real credentials — and even that wedge is unproven, time-boxed by competitors, and behind two named structural bypasses that must be closed or contract-named first.**

**Confidence: high** on repository facts (every load-bearing claim re-verified directly; see §2); **medium-high** on the market picture (competitor existence and capabilities verified against live primary sources by the stage-2 market cross-check on 2026-08-31/09-01; star counts and activity levels sampled, not exhaustively re-verified); **low, by construction**, on every forward-looking statement in §14–§16, which is why each carries a measurable gate.

### The one-page decision summary

1. **What is real:** a 9-crate Rust workspace (~29.9k LOC), 361 unit/integration tests, 672 in-file policy tests, 155 rules across 10 packs (80 allow / 66 approval_required / 9 deny — counted three independent times, this review included), a 90-incident / 255-scenario threat ledger with a machine checker (green), a self-adversarial bypass harness, measured performance numbers at every layer, an interruption budget that measurably refused the founder's own severity instincts twice (`docs/DECISIONS.md` 2026-08-31 entries), a deny-safe `/dev/tty` approval UX, a quarantine flow recorded end-to-end, telemetry that is off by default and provably has no upload code (`cargo tree -p af-telemetry` → `af-core`, `serde`, `serde_json` only), and an alpha banner — "not a production security boundary" — printed by the binary on every run (`crates/af-cli/src/run.rs:42`). The measurement culture is not decoration; it is enforced, and it is the project's most distinctive asset.
2. **What is not real:** the "firewall" in the name, as a boundary claim. The repository's own bypass harness measured `io_uring` as a **complete bypass** (an `IORING_OP_OPENAT` with write intent produced zero events in every filter mode; `research/bypass/FINDINGS.md:86-88`). The monitor is a same-user process attackable through `ptrace` attach, `process_vm_writev`, `/proc/<pid>/mem`, and `pidfd_send_signal` — the seccomp filter holds only `kill`/`tkill`/`tgkill` against the monitor pid (`crates/af-monitor/src/seccomp.rs:311-313`) and the code itself documents `pidfd_send_signal` as unheld (`seccomp.rs:43`). Inherited/live descriptors bypass the `open`/`connect` observation points. The mechanism stack (unprivileged Landlock + seccomp-notify + pidfd) was published independently as **Sandlock** (arXiv 2605.26298, ASPLOS'26 Agentic OS workshop), so the mechanism is not novel; and vendor sandboxes (Codex CLI, Claude Code) are now default-on and free, eBPF lineage enforcement exists (**ActPlane**), and CrowdStrike markets agent-runtime tracing on the endpoint (2026). What survives competition is a **bundle** — external unprivileged whole-tree supervision + human approval at a descendant's exec boundary with provenance context + stateful deterministic rules + replayable evidence — which no verified competitor ships together, but which is also the hardest part to price.
3. **What is broken right now:** the repository's own gates are not all green. `count-rules.py` exits 1 (three unclassified correlation rules). `tests/e2e.sh` failed 1/54 assertions in this review's re-run (T8; a second reviewer's run failed T8+T11), though the M6 ledger recorded 54/54 at ship time — the suite is nondeterministic. One `af-monitor` unit test was observed flaky by the stage-2 verification (passed on retry and in this review). There is no CI, no SECURITY.md, no signed release, no tags, stale rule counts in three governing docs, and a gitignored on-disk benign-corpus FAIL line (`research/bypass/results/benign-summary.txt:4`) that contradicts the "zero quarantines" narrative.
4. **The integrity incident:** an uncommitted, open ticket `[af-9]` ("Sense audit-trail tampering: trace writes, history and transcript erasure") plus one log event existed in the working tree when the first review workflow started at 22:41 on 2026-08-31; the HEAD commit message claims to file it; the files' mtimes fall inside the review window (22:55); afterwards the tree was clean and the ticket does not exist anywhere in tracked state. What happened, and who or what reverted it, is **not establishable from available evidence**. This is disclosed in full in §2.5 and §8; it does not change the technical verdicts, but it must ride with any use of this review as evidence.
5. **The decision:** do not attempt to distribute or monetize the current artifact. First make the record trustworthy (gates green, CI, signing, disclosure channel, threat-model honesty), close or contract-name the two structural bypasses (io_uring, inherited descriptors), ship the headless `guard --ci` mode that the evidence actually supports, and run the ≤$25k falsification program in §15 with pre-registered kill thresholds. Go/pivot/stop criteria are in §16.

**Bottom line for a funder or adopting organization:** this is the most disciplined pre-product codebase in the category this review examined, built by someone who measurably refuses to fool themselves. It is a hire-quality portfolio and a credible open-source research project today. It is not yet a company, not yet a security product, and not yet safe for a third party to install — mostly for cheap, mechanical reasons that §14 sequences precisely.

---

## 2. Methodology, commands, coverage map, limitations, and integrity note

### 2.1 Review pipeline and inputs

Two waves of review produced this report:

- **Wave 1** (`wf_31658243be66`, started 2026-08-31 22:41): twelve first-pass agents — repository inventory, two *independent* deep market studies, governing docs, four code partitions (core+monitor; policy+provenance+approval; recorder+correlate+telemetry+cli; policies+tests+demo+ops), mechanism research, threat research, all technical docs, and a Rohrpost audit. The workflow **failed at its Challenge phase** ("Workflow sandbox sent an invalid agent request"; confirmed in `workflow.json`), so wave 1 produced no challenge/convergence/report stages.
- **Wave 2** (stage 2): eight adversarial and integrative reviews — technical falsification, product falsification, trust/UX/commercial, verification (gate re-runs), coverage cross-check, market cross-check (live primary-source re-verification), positive thesis, and remediation plan.
- **This report:** the lead reviewer re-verified every load-bearing claim directly against the repository, resolved the contradictions between reviewers (§2.4), and integrated. Where this report cites wave-1 or stage-2 material that could not be re-verified (e.g., market activity levels), that limitation is stated.

### 2.2 Commands run by this reviewer (all read-only; working tree preserved clean)

```
git status / git log --format='%an %ad' / --format=%G? / git show --stat c7ca6f0 / git tag -l / git stash list / git reflog
git check-ignore -v research/bypass/results/benign-summary.txt ; git grep -l "af-9"
python3 - <<rule count>>            → 10 packs, 155 rules: allow 80 / approval_required 66 / deny 9
python3 research/spikes/landlock/tests/count-rules.py → 3 UNCLASSIFIED correlation rules, exit 1
python3 research/threats/check.py   → incidents on disk: 90 | scenarios on disk: 255; ledger agrees
cargo fmt --check                   → PASS (no output)
cargo test --workspace -- --list    → 361 tests
cargo test -p af-monitor --lib tests::simple_session_reports_exec_and_exit -- --exact → 1 passed (0.01s)
bash tests/e2e.sh                   → 53 passed / 1 failed (T8 "the detach fact fired"); stage-2 verification observed 52/54 (T8, T11)
./target/release/agent-firewall policy check policies → "155 rule(s) are valid, 0 warning(s)"
./target/release/agent-firewall policy test           → "672 policy test(s) passed"
./target/release/agent-firewall --help / run --help   → command surface verified (run/replay/tree/correlate/policy/telemetry/doctor)
cargo tree -p af-telemetry          → af-core, serde, serde_json only
rp ready / rp stats / rp doctor     → "No actionable work. The tube is empty."; 33 events / 9 tickets; all checks ok
sha256sum .rohrpost/{log.jsonl,tickets.jsonl} before and after rp commands → identical; git status clean after
```

Not re-run by this reviewer (cost/benefit): full `cargo clippy` and `cargo test --workspace` (stage-2 verification ran both; clippy clean, workspace tests green except one intermittent `af-monitor` flake that passed on retry and in this review's targeted re-run), `research/bench/quiet-check.sh` (stage-2 verification: 58 commands — 53 quiet, 5 report-only, 0 stopped; 13 dangerous stopped, 0 missed), and any network fetch (market claims inherit the stage-2 market cross-check's live verifications of 2026-08-31/09-01).

### 2.3 Complete coverage map

| Area | Wave-1 agent | Stage-2 lens | This reviewer's re-verification | Verdict |
|---|---|---|---|---|
| `crates/af-core`, `af-monitor` | 5 (final lost; raw reads retained) | technical falsification | seccomp kill-filter scope, pidfd gap, `AUDIT_ARCH_X86_64`, yama text, Landlock writable-TMP, lib.rs perf statements — all confirmed at cited lines | **Substantively reviewed** |
| `crates/af-policy`, `af-provenance`, `af-approval` | 6 (final lost) | technical falsification (partial), trust-ux | `DEFAULT_TIMEOUT` 120s, deny-safe approval design cited by trust-ux spot-checked | **Substantively reviewed** |
| `crates/af-recorder`, `af-correlate`, `af-telemetry`, `af-cli` | 7 (final lost) | trust-ux (deep) | telemetry dep tree re-run; CLI surface re-run; `DATABASE_URL` allowlist line confirmed | **Credibly reviewed** |
| `policies/*.yaml` (10 packs, 5,380 lines) | 8 | product falsification, verification | counts re-derived independently (155/80/66/9); 672 policy tests re-run green; no rule consumes agent identity or sensor event kinds (grep re-run: matches for "identity" are regex literals/titles only) | **Credibly reviewed** |
| `research/spikes/*`, `research/bypass/` | 9 (final lost) | technical/product falsification | io_uring finding, 1.16–1.92× filter table, 11.0×/12.5× product rows, 10× ptrace statement, 47.6% TOCTOU — all confirmed at cited lines | **Credibly reviewed** |
| `research/threats/` | 10 | product falsification, verification | `check.py` re-run green at 90/255; 90 incident files and 10 axis catalogs counted on disk | **Credibly reviewed** |
| `docs/*.md`, README, PROJECT, AGENTS | 4, 11 | all four stage-2 files | every staleness claim re-verified with line numbers (§7) | **Credibly reviewed** |
| `.rohrpost/` | 12 (final lost) | verification (hash-based) | ticket/log state at HEAD re-read; `rp ready`/`doctor` re-run with hash stability; incident timeline re-derived (§2.5) | **Reviewed twice + this review; incident open** |
| Market (external) | 2 + 3 (finals lost; raw scrapes retained) | market cross-check (live) | accepted with confidence labels; not re-scraped here | **Credibly researched; fast-moving target** |
| `.pi/` skills & tooling | 1 (inventory only) | none | not deep-reviewed | **Acceptable omission** (process metadata; its `check.py` gate exercised by three parties) |
| `docs/ARCHITECTURE-OVERVIEW.html` | 1 (noted, generated) | none | not reviewed; predates the 08-31 ARCHITECTURE.md by ~14h of ships | **Named gap; low materiality** |
| `Cargo.lock` dependency/supply-chain audit | inventory only | trust-ux (notes only) | no `cargo audit`/`cargo-deny` run by anyone | **Real gap for a security product** |
| Untracked `.rohrpost/{archive,shadow,templates}` | none | none | directory listings only (archive and shadow empty) | **Not examined; immaterial** |

Not credibly reviewed, final list: deep `.pi/` content, `ARCHITECTURE-OVERVIEW.html` freshness, dependency advisory scan, untracked `.rohrpost` subdirectories. None is decision-critical; all are named so "exhaustive" is not overclaimed.

### 2.4 Contradictions between reviewers, resolved

This report resolves contradictions explicitly rather than averaging:

1. **"361 passing tests" vs. a failing `cargo test --workspace`.** Both true at their moments: 361 is the correct count (re-derived via `-- --list`), the workspace run failed once on `af-monitor::tests::simple_session_reports_exec_and_exit` (left 4, right 1) and passed on immediate retry and in this review. Resolution: **the suite is environment-sensitive; quote "361 tests, one observed flake."**
2. **e2e 54/54 (M6 ledger, at ship time) vs. 52/54 (stage-2 verification) vs. 53/54 (this review).** Resolution: **the e2e gate was green when recorded and is not green now; T8 is reproducibly failing across two independent runs; T11 failed once and passed once.** The failure is in assertion/text-matching or race sensitivity — the expected events (`detached_descendant`, `killed_subtree_returned`) are visibly present in the traces. The gate needs deterministic repair; the events exist.
3. **F2 (inherited descriptors) breadth.** Technical falsification asserted the launcher inherits descriptors from its environment; the coverage cross-check established that Rust `std::process::Command` closes inherited non-stdio fds by default, so the *launcher-inheritance* half was overstated. Resolution: **the in-tree vector (a process opens a socket/file and hands the live fd to a descendant via fork or SCM_RIGHTS; subsequent writes bypass the open/connect observation points) is valid and unmitigated; the launcher vector is not the live concern. The finding stands in substance, narrowed in breadth.**
4. **"One committed FAIL line" (product falsification).** False as stated: the FAIL line exists on disk (`research/bypass/results/benign-summary.txt:4`) but the file is gitignored (`.gitignore:35`), not committed. Resolution: **the benign-corpus regression is real and on disk; the word "committed" is wrong.**
5. **"Every commit dated 2026-08-31" (trust-ux).** False: 57 commits span 2026-08-28 (23), 08-29 (5), 08-30 (8), 08-31 (21). Resolution: **the bus-factor point stands; the date claim is wrong.**
6. **Two "8.8×/8.1×" content-capture numbers** in different docs are different measurements of the same rejected design (content capture over connections), not drift. Resolution: cross-pointer warranted, no correction.
7. **Performance framing.** "~10× on builds" (product falsification) is an extrapolation; the repo's own number is "a file-heavy workload under `ptrace` alone was about ten times slower" (`crates/af-monitor/src/lib.rs:113-116`), with the product measured at 11.0× and product+sensor at 12.5× on the file-heavy synthetic W2 (`research/spikes/inprocess/FINDINGS.md:145-146`). Resolution: **10× is the repo's own file-heavy measurement; applying it to "a normal build day" is inference, flagged as such.**
8. **GuardAgent as a "direct competitor"** (first-pass framing) vs. category error (market cross-check). Resolution: **category error — an LLM-judgment guardrail with no OS boundary; retained only as evidence of academic crowding.**

### 2.5 Integrity note — the `.rohrpost` working-tree incident

Stated plainly, without concealment and without overclaiming:

- **Established facts (high confidence).** At 22:26:07 on 2026-08-31 the maintainer committed `c7ca6f0` ("Record the audit-trail-erasure shape: SC evade-25, and file it as af-9"). The commit touches only `research/threats/LEDGER.md` and `research/threats/scenarios/evade.md` — **it contains no `.rohrpost` change and no af-9 ticket**; its body says "filed as AF-an4nm7." At 22:41 the first review workflow started; agent 1's captured `git status` shows `.rohrpost/log.jsonl` and `.rohrpost/tickets.jsonl` modified (tracked, uncommitted), and its ticket dump lists **ten** tickets including open `an4nm7` — "[af-9] Sense audit-trail tampering: trace writes, history and transcript erasure" — and 34 log events. Both files' mtimes are 22:55:34, inside the workflow window. By the stage-2 verification (~23:31) and in this review, the tree is clean, both files match HEAD exactly (9 tickets, 33 log lines), `git stash` is empty, and the reflog contains only commits. No tracked file anywhere references `af-9`/`an4nm7` (re-verified by `rg` and `git grep`); the ticket's identity and title survive **only** in the wave-1 transcript.
- **What cannot be established.** Who or what destroyed the uncommitted state — a `git` path-restore (which leaves no reflog entry), an `rp` operation, or human action. The stage-2 verification excluded the *read-only* `rp` commands as re-writers in its own window (before/after hashes identical), and this review reproduced that exclusion. The parent workflow's report that `.rohrpost` was modified before the first workflow but became clean after nominally read-only ticket-audit commands **cannot be causally reproduced or attributed from available evidence**.
- **What must not be claimed.** Neither "nothing was lost" nor "content X was lost." What is proven: **the uncommitted state of an open ticket and one log event no longer exists, was destroyed during a review window that was supposed to be read-only, and the HEAD commit message misdescribes its own content** (says a ticket was filed that no commit contains). The downstream consequence is concrete: `MILESTONES.md` and the evade-25 research now point at follow-up work whose only surviving record is a review transcript, and the forward queue is empty (§8).

This incident does not overturn any substantive verdict in this report; every technical claim re-verified against the repository held. But it must ride with this review wherever it is used as evidence, and it motivates remediation item P0-8.

### 2.6 Environment

All measurements, including this review's, come from one machine: Fedora 43, kernel 7.0.9, x86_64, `rustc` 1.97.1, uid 1000, `yama/ptrace_scope=0`, `kernel.io_uring_disabled=0`, host under varying load (the in-process spike recorded load 1.8–3.9). Every performance and quiet number in this report is therefore **single-host evidence**; §6 treats what that does and does not license.

---

## 3. What the project is — as-built versus as-directed

### 3.1 As-built (ARCHITECTURE.md §§1–7, verified against code)

**Agent Firewall is a Linux launch wrapper for a coding-agent session.** You run `agent-firewall run -- <command>`; it launches the command under `ptrace`, follows every descendant via `PTRACE_O_TRACEFORK/CLONE/VFORK`, stops each new program at the `execve` boundary before it runs, and — through a small seccomp filter (`RET_TRACE` on selected syscalls) — also holds write-intent opens and outgoing `connect`s *inside* already-running programs. Facts are normalized into one `af-core::Event` schema, attributed through a provenance chain (session root → acting process), matched against a deterministic YAML rule pack (155 rules; allow / approval_required / deny; quarantine for tamper), and written to an opt-in local JSONL trace that `replay` re-judges under current rules. A Landlock ruleset (the "kernel floor," `--landlock on` default) denies credential stores, system trees, and raw devices at kernel grade, answering six of the pack's questions without a prompt. Agent identity (a detector registry, noisy-OR at tag ≥ 0.75) propagates through the tree; `setsid`/daemon escapes are flagged. An in-process LD_PRELOAD sensor exists as a research spike that reports (file deletes/renames, library loads, env changes) and **never decides**. Correlation compares the monitor's trace to the sensor's post-hoc and raises discrepancy events; two correlation rules quarantine. Tamper sensing (signals to the monitor, preload stripping, tree escape) exists with a real interactive quarantine flow. Telemetry is opt-in, granular over five scopes, redacted, pseudonymized, local-only, and provably has no upload code. The binary prints "alpha release — not a production security boundary" on every run.

**What it is not, as-built:** not a sandbox; not cross-platform (Linux only; the seccomp filter is x86_64-only — `crates/af-monitor/src/seccomp.rs:336`); not attach-mode (it sees only trees it launched); not live-correlation (post-hoc only — `docs/DECISIONS.md` 2026-08-31, newest entry, is binding); not a privileged supervisor (user-space, same uid as the target); not distributed (build from source; no releases, tags, or CI); not a product with a customer (zero external adoption evidenced anywhere in the repository).

### 3.2 As-directed (DIRECTION.md, adopted 2026-08-30 — direction of record)

The direction widens the target: a **cross-platform** security and observability layer for AI coding agents; vendor-neutral; execution-tree responsibility; **not a sandbox**; several sensors instead of one mechanism; AI-controlled process identity and generic agent detection (including agents *not* launched by the firewall — attach mode, explicitly directed, explicitly unbuilt); tamper detection as a first-class security signal; early-access telemetry feeding a **telemetry → research → detections → deployed protection** loop; an open-source/commercial split in which sensors, engine, and basic rules are open (Apache-2.0) and the corpus, feeds, and research automation are private ("the value is the maintained rule feed" — `docs/PRODUCT.md` §4); a consumer edition (no root, disable-able, local) now and an enterprise edition (privileged service, central policy, un-disable-able protection, central audit) later.

**The gap that governs this review:** the direction's language ("security and observability layer," "intervenes before damage occurs") is written at a fidelity the as-built sensors cannot support against a hostile peer, while the direction's own §2 also insists measurement decides mechanisms. The repository's honesty discipline (as-built vs. as-directed separation is project law) has largely held — this review found **no as-directed item promoted to as-built anywhere** — but §7 documents the places where as-built text went stale *behind* shipped work, and §5 documents where the *name* of the product ("firewall") and §1's framing outrun the measured boundary. The soundness rule is the model of the project at its best: "a path read from the memory of the judged program is never the reason to allow" (`docs/DETECTION-RESEARCH.md` §2; 47.6% measured wrong under two threads — `docs/DETECTION-RESEARCH.md:71`).

### 3.3 The honest one-sentence description

This report's standing recommendation for how to describe the artifact: **"A Linux launch wrapper for cooperative or accidental coding agents: provenance-attributed policy prompts, deterministic pre-call refusal at the exec and write/connect boundaries, a conservative Landlock floor, and replayable local evidence. Not a sandbox, not host EDR, and not protection against a hostile same-user process."**

---

## 4. Implementation review — nine crates, policies, tests, demo, build/release/supply-chain

Approximately 29,928 lines of Rust across nine crates; 5,380 lines of policy YAML across ten packs; 361 tests (per-crate: af-monitor 58, af-policy 75, af-approval 50, af-cli 46, af-core 44, af-provenance 28, af-telemetry 27, af-recorder 21, af-correlate 12).

**`af-core` (~3.9k LOC).** The normalized event schema — one `Event` value across ptrace, seccomp, Landlock, and the sensor — plus `ProcessInfo`, display truncation, and the identity subsystem (`TAG_THRESHOLD = 0.75`, noisy-OR over five detector families; corpus precision 1.000 / recall 0.957 on 53 synthetic fixtures, the one miss the bare name `pi`). The schema is clean and genuinely load-bearing: every sensor and the trace format consume it. Limits: the identity corpus is synthetic (no real agent was installed — the repo says so itself), detection inputs are attacker-controlled, and **no rule in any pack consumes agent identity today** (grep-verified: matches for "identity" in packs are regex literals and titles). `event.rs:248,256` define `FileDelete`/`FileRename` — emitted by the in-process sensor only; the external observer path has no delete/rename fact, which is the accurate core of README's stale-sounding claim (§7).

**`af-monitor` (~5.7k LOC).** The heart: tracer (launch, follow, exec stop), seccomp filter (write-only opens / all-opens / off; `RET_TRACE`), Landlock floor planner, `/proc` reader, input capture, caps doctor. Code quality is high and self-documented with measured numbers (`crates/af-monitor/src/lib.rs:113-116`). The security-relevant facts, all verified at line level: the filter holds `kill`/`tkill`/`tgkill` **only when the target is the monitor pid** (`seccomp.rs:311-313`); `pidfd_send_signal` is documented as unheld (`seccomp.rs:43-44`); `AUDIT_ARCH_X86_64` is hard-coded, foreign ABIs fall back to exec-only coverage with a warning (`seccomp.rs:336,393`); yama `ptrace_scope=0` is presented as a supported unprivileged configuration ("any process may trace" — `caps.rs:189`); the Landlock plan grants full write to the work tree, `/tmp`, `/var/tmp`, `/var/cache` (`landlock.rs:358`) so credentials created under the work tree or `/tmp` are unprotected by the home carve-out (the code's own docs admit the `.ssh`-under-`/tmp` case — `landlock.rs:594`); the floor cannot be relaxed mid-session (`--landlock off` starts a new session); paths read from tracee memory via `/proc/<pid>/mem` are advisory only. `ptrace` means setuid is not honored under trace and `sudo` cannot raise privilege — disclosed in README. One observed flaky test (`tests::simple_session_reports_exec_and_exit`).

**`af-policy` (~4.9k LOC).** The deterministic rule engine: YAML packs with allow/ask/deny decisions, in-file tests (672 pass), quarantine flags, and the builtin pack compiled in via `include_str!` (`crates/af-policy/src/builtin.rs`). The engine is genuinely stateful relative to the category: session memory (7 rules), correlation discrepancy rules (3), baselines and thresholds. Gaps: the pack/floor drift guard `count-rules.py` **fails today** (three correlation rules unclassified — exit 1 reproduced); no rule consumes identity or sensor event kinds; user packs load from `--policy` paths with **no integrity checking**; there is no update channel — "updates" means "recompile."

**`af-provenance` (~1.9k LOC).** Chain building from session root to acting process, identity propagation, unlink/escape facts. Solid, small, well-tested (28 tests); the demo's `migrate.sh → psql DROP DATABASE` attribution depends on it and works.

**`af-approval` (~2.2k LOC).** The best-executed UX in the repository: `/dev/tty` discipline (never reads the agent's stdin), deny-safe on every abnormal path (empty answer, 3 unknowns, 120s timeout — `terminal.rs:17`, closed tty, no tty), hostile ANSI/OSC stripping from process-controlled text, all-matched-rules display, session memory keyed on stable fingerprints with temp-file masking, `NO_COLOR` honored, color never the only channel. Gaps: the 120s freeze of the whole tree is invisible in the prompt (no countdown); `allow for session` deliberately does not persist across sessions (privacy-correct, re-asks tomorrow); no way to view rule text from the prompt.

**`af-recorder` (~2.1k LOC).** Opt-in `--trace` JSONL with three retention levels (default `balanced` drops unmatched actions and stdin content — reasoned from replay parity: "an action that no rule matched is dropped, and it could not change a verdict"), durable events flushed inline so a SIGKILLed monitor leaves 2 lines (against M1's 1 — M4 ledger). Gaps: files created with `File::create` → umask-dependent 0644 (raw argv, `DATABASE_URL` values — readable by other local users); no fsync/hash-chain/protected storage; same-user target can delete or truncate the trace; no rotation, no `trace redact`, no lifecycle.

**`af-correlate` (~1.5k LOC).** Post-hoc comparison of monitor trace vs. sensor trace/registration; raises four discrepancy kinds; two rules quarantine. The M5 gate refused a write-open comparison rule **with numbers** (30 firings on one 28-second benign session) — the discipline working as designed. Live correlation is explicitly future work (newest DECISIONS entry).

**`af-telemetry` (~2.6k LOC).** Off by default, double opt-in (flag + consent file), five granular revocable scopes, local inspectable outbox with `inspect`/`destroy`, redaction-first with negative tests proving secrets/pids/hostnames/baselines never travel. The strongest sentence in the repository — "nothing is sent anywhere; no upload code exists" — is **dependency-graph-true** (`cargo tree`: `af-core`, `serde`, `serde_json` only). Gaps: true, not enforced (no `cargo-deny` ban); known redaction blind spots (JWT, PEM, generic base64); `DATABASE_URL` userinfo (`postgres://user:pass@host`) is captured raw into local traces because the name is allowlisted (`procfs.rs:25`) and carries no secret marker; consent file and samples are 0644.

**`af-cli` (~5.1k LOC).** `run` / `replay` / `tree` / `correlate` / `policy` / `telemetry` / `doctor` — a coherent, honest surface. `doctor` is the right #1 support tool (alpha disclosure, per-capability table, inactive-rule count under current filter mode, consent state, exit 1 when the machine cannot hold a program). The alpha banner prints on every run (`run.rs:42`) and is asserted in tests. Missing: `doctor --json`, version/build info, any log file (everything is stderr; agent UIs swallow stderr).

**Policies (10 packs, 155 rules).** 80 allow / 66 approval_required / 9 deny; five of the 66 questions are quarantines; six of the 66 are answered by the kernel floor. Content is threat-ledger-derived and generally conservative (recoverable operations like `kubectl delete pod` report, not stop). The counts disagree across governing docs (147/152/155 — §7). Tests: 672 in-file, all green (re-run).

**Tests and demo.** 361 Rust tests; 54-assertion e2e (`tests/e2e.sh`) using local fixtures, fake `psql`, marker files — safe, realistic about mechanisms, and honest that it exercises no real database, cloud, agent, or hostile kernel boundary. The e2e gate is currently red-ish (T8 reproducible; T11 flaky — §2.4). The demo (`demo/`) stages the flagship scenario (agent → bash → `migrate.sh` → `psql DROP DATABASE`) and admits its `psql` is fake. Quiet-check bench: 58 commands, 53 quiet / 5 report / 0 stopped; 13 dangerous stopped / 0 missed (stage-2 run).

**Build, release, supply-chain.** Clean workspace build (fmt/clippy green; clippy re-verified by stage-2), minimal dependencies (admirably so — the telemetry no-network proof *is* the dep tree), Apache-2.0 throughout, `version 0.1.0`. And then: **no CI of any kind** (no `.github`, no `.gitlab`), no tags, no releases, no signing (57/57 commits unsigned, `%G?` = N), no SECURITY.md / CONTRIBUTING / CODE_OF_CONDUCT / NOTICE / CHANGELOG, a placeholder repository URL (`Cargo.toml:23` → `github.com/agent-firewall/agent-firewall`, which does not exist), no SBOM/`cargo auditable`/`cargo-deny` (no dependency advisory scan was ever run), and all raw research results gitignored (`research/bypass/results/`, `.gitignore:35`) so the committed tree cannot reproduce the headline benign/perf artifacts. For a security product whose trust posture is its main asset, this is the largest cheap-to-fix deficit in the repository.

---

## 5. Security boundary and threat model — guaranteed, advisory, bypassable, unknown

The single most important analytical act for this project is separating four epistemic states. The repository's own discipline makes this easier than usual; its own bypass harness is the primary evidence.

### 5.1 Guaranteed (measured, deterministic, re-runnable)

- **A launched descendant is stopped at `execve` before its new program runs one instruction** (ptrace exec stop; kernel-guaranteed for traced children). This is the product's hardest primitive.
- **Selected syscalls (`open`/`openat`/`openat2` with write intent under `write-only`; every open under `all-opens`; `connect`; unlink/rename variants) are held before execution inside traced processes on x86_64** (seccomp `RET_TRACE`). The M5 ledger records `spawn_reported_unseen` measured 0/0 — "the exec stop is a kernel guarantee" — and ships no rule because there is nothing to detect.
- **The Landlock floor denies a fixed set at kernel grade** (credential stores, system trees, raw devices; `--landlock on` default) at a measured 0.98×–1.07× cost, with 0/6 escape attempts in its spike, and every floor-caused `EACCES` is explained with its rule class (L2 explainer).
- **Fail-closed on monitor loss:** `PTRACE_O_EXITKILL` kills the tree if the monitor dies; a traced call with no monitor returns `ENOSYS` — the program breaks rather than proceeds unobserved.
- **Deny-safe approval:** every abnormal approval path (timeout, closed tty, garbage input) denies.
- **Telemetry non-exfiltration:** no upload code exists, dependency-graph-verified (true today; not structurally enforced — see P0-4).

### 5.2 Advisory (visible, honest, but not a control)

- **Paths read from tracee memory** (pathname arguments, sockaddrs) label observations and denials; they are never (per the soundness rule, followed in code as shipped) the basis of an allow. Measured wrong 47.6% of the time under two threads (`docs/DETECTION-RESEARCH.md:71`). The rule is correct; the structural risk is future drift as policy grows — nothing at the type level prevents an `allow` from someday consuming pointer-derived data ("no rule matched ⇒ allow" is already a path-influenced default).
- **Agent identity** (tag ≥ 0.75, noisy-OR): a label, not a principal. No rule consumes it; inputs are attacker-controlled; attach mode is unbuilt.
- **In-process sensor facts** (file_delete, file_rename, library_load, env_change, file_read): report-only by design and by shipped behavior — no rule matches these kinds (grep-verified). "A sensor is not a boundary" is project law and is honored.
- **Correlation discrepancies:** post-hoc findings judged on replay; two rules quarantine. The finding cannot stop the action that produced it.
- **Tamper sensing:** signals toward the monitor and preload stripping are sensed and judged (four shapes, 5-rule pack, negative tests); the seccomp hold on `kill`/`tkill`/`tgkill`-to-monitor fires before the signal runs. This is a **narrow scripted-kill defense, not monitor integrity** (below).

### 5.3 Bypassable (structural, named, with evidence)

1. **io_uring — complete bypass, measured.** One `io_uring_enter` performing `IORING_OP_OPENAT` with write intent produced **zero events in every filter mode** (`research/bypass/FINDINGS.md:86-88`; scenario evade-15; live on the reference host with `kernel.io_uring_disabled=0`). Read, write, connect, send, directory enumeration and deletion are all submittable through the ring. Neither the kernel filter nor the sensor records anything. Disclosed in README (`README.md:289-293`); mitigations are "future work" in the findings. A sysctl check is posture, not enforcement.
2. **Same-user attack on the monitor.** The monitor is an ordinary process at the target's uid. The seccomp filter covers only `kill`/`tkill`/`tgkill` when aimed at the monitor (`seccomp.rs:311-313`). Unheld surfaces: `pidfd_send_signal` (documented, `seccomp.rs:43`), `ptrace` attach, `process_vm_writev`, `/proc/<pid>/mem`, `pidfd_getfd`. yama=0 — "any process may trace" — is presented as a supported configuration (`caps.rs:189`). There is no `PR_SET_DUMPABLE(0)`, no privilege separation. External SIGKILL of the monitor is fail-closed (EXITKILL kills the tree) but generates **no tamper event**.
3. **Live/inherited descriptors.** Anything already open (socket, file, memfd, pidfd) needs no `open`/`connect`; all subsequent `write`/`sendmsg`/`splice`/`sendfile` are outside the filter. In-tree inheritance and `SCM_RIGHTS` passing make the boundary non-local (launcher-inheritance is *not* the live vector — std `Command` closes non-stdio fds — but nothing closes what the tree itself opens).
4. **Landlock's scope.** It mediates path-hierarchy rights only: no argv, hostnames, SQL, chmod, ioctls, most network forms; exec from an anonymous fd is allowed; broad write grants to work tree + `/tmp` + `/var/tmp` + `/var/cache` (`landlock.rs:358`) leave credentials created there unprotected; irrevocable per session, which trains `--landlock off` when a legitimate need arises.
5. **x86_64-only filter; foreign ABIs keep exec-only coverage** (32-bit guests warned, not filtered; `seccomp.rs:336`).
6. **Monitor discoverability.** `TracerPid` and `Seccomp` are visible in `/proc/self/status` (documented in the repo): a hostile payload can run clean under observation and act when unobserved.
7. **Tree ≠ world.** Helpers, browsers, systemd user services, the Docker daemon, remote services — anything outside the launched tree — can perform the effect; an observed `connect` is not protocol content (content capture was measured at 8.8× and correctly rejected).

### 5.4 Unknown (must not be converted into claims)

Kernel-version breadth beyond the one Fedora host (Landlock ABI, seccomp/io_uring behavior, Yama combinations); real-agent identity precision/recall (fixtures only); policy quality on real dev days (the benign corpus is a curated 58-command, ~28-second synthetic session; one on-disk run mode contains a quarantine FAIL — `research/bypass/results/benign-summary.txt:4`); hostile multithreaded races beyond the measured path case (sockaddr races, `openat2` struct races, dirfd mutation); monitor restart/handoff semantics; namespace transitions; telemetry privacy under adversarial content; Windows/macOS viability (M7 is a paper survey stamped "Nothing here was run").

### 5.5 The verdict on the boundary

For an **accidental or careless agent** (normal tools, no adversarial intent), the as-built system provides real, measured, explainable friction at true boundaries — viable and valuable. For a **hostile agent with its user's privileges**, the as-built system is not a boundary: it is a same-user observer with two structural blind channels (io_uring, live descriptors) and an attackable monitor. No amount of better rules or agent detection changes that; only a privileged/separate-identity supervisor, kernel-side enforcement, or sandbox isolation does. The project's direction (§10 enterprise tier) gestures at this but builds none of it. **The correct public posture — which the binary banner already approximates — is: cooperative-agent guardrail, not hostile-agent boundary.** The product *name* remains the biggest single overclaim risk (§10, overclaim guardrails).

---

## 6. Research quality and reproducibility

### 6.1 What is genuinely excellent

- **Every headline number traces to runnable code.** This review re-verified: 10× ptrace file-heavy (`crates/af-monitor/src/lib.rs:113-116`); filter 1.16×/1.33×/1.22× recommended config, 1.92× all-opens (`research/spikes/seccomp-ptrace/FINDINGS.md:73-84,390`); content capture 8.8× rejected; sensor-alone 1.46×/1.77×/1.42× and product 2.36×/11.0×/2.99×, product+sensor 12.5× on W2 (`research/spikes/inprocess/FINDINGS.md:145-146`); Landlock floor 0.98×–1.07× with 0/6 escapes; TOCTOU 47.6% with 2000/2000 refusals (`docs/DETECTION-RESEARCH.md:71,217`); 98% of interesting corpus actions (1205/1231) invisible to argv (M2 spike).
- **The bypass harness is a standing asset.** 77 technique runs plus the benign corpus, a hold/see/silent matrix in which every silent cell carries a named structural cause, regenerated in ~2 minutes. It caught the product erasing its own evidence when the monitor is killed (M1: one-line trace; M4 improved to two lines) — adversarial self-measurement no examined competitor publishes.
- **The threat-research pipeline is real and checkable.** 90 incident reports across 10 axes (real 2024–2026 events: Claude Code home wipes, Cursor drive wipes, Replit prod-DB wipe, Kiro environment deletes, Shai-Hulud, xz, GlassWorm, "Comment and Control") → 255 scenarios, with `check.py` green (re-run: ledger agrees with disk). Two live URL spot-checks during wave 1 (oddguan.com Comment-and-Control; koi.ai GlassWorm) confirmed the incident reports are faithful to primary sources — research capability, not SEO aggregation. Per the direction, research agents never publish production rules; every rule is human-gated with negative tests.
- **Null results are recorded and honored.** `spawn_reported_unseen` 0/0 ships no rule; 8.8× content capture is cut; the interruption budget refused two severity-motivated rules with numbers (`docs/DECISIONS.md` 2026-08-31) — the git-maintenance detach rule (fires on every commit) and the write-open correlation rule (30 firings / 28-second session). A governance process that measurably overrules its founder's severity instincts is rare at any stage.

### 6.2 What limits it

- **Single machine, single maintainer, loaded host.** Every number is Fedora 43 / kernel 7.0.9 / x86_64 / uid 1000 / yama 0 / io_uring enabled. No number has ever been replicated on a second host. The in-process spike itself notes load 1.8–3.9 during measurement.
- **Synthetic workloads.** W1/W2/W3 are harness workloads; "a read-only open is 99.7% of the open traffic of a normal build" derives from the synthetic W2, not a real build tree. The benign corpus is ~28 seconds of scripted git/cargo/npm on synthetic projects — no docker, terraform, kubectl-with-real-config, venvs, or node-gyp.
- **Raw results are gitignored** (`research/bypass/results/`, `.gitignore:35`) and exist only on the reference machine. The committed tree cannot reproduce the committed claims without re-running (which is at least possible — the harness is committed).
- **The corpus is public** — the bootstrap corpus that justifies the whole loop is readable by every competitor.
- **Ledger hygiene drift exists:** evade-04 (memfd) and evade-06 (LD_PRELOAD) are still marked `gap` in the ledger while the shipped pack now contains rules matching exactly their signals; the ledger's "blocked" count semantics changed after M4/M5, leaving `MILESTONES.md:243` stale.
- **Coverage numbers are corpus counts, not field prevalence.** "255 scenarios" measures the catalogue, not the world.

### 6.3 Reproducibility scorecard

Reproducible today (committed code + committed docs, re-run by this review or stage 2): rule counts, policy validation and tests, threat-ledger integrity, fmt/clippy, unit tests (one flake), quiet-check, bypass harness mechanics. Not reproducible from the committed tree: exact benign/perf artifacts (gitignored results), any cross-host claim, e2e determinism (currently red-adjacent). Verdict: **research quality high for a solo pre-product effort; reproducibility infrastructure medium; both degrade sharply the moment a claim leaves this one machine — which is why multi-distro replication is P1-2.**

---

## 7. Documentation consistency and governance

The documentation set (PROJECT.md, README, 10 `docs/*.md` files, per-crate doc comments, per-spike FINDINGS) is voluminous, disciplined in structure (direction vs. architecture vs. decisions vs. milestones), and mostly accurate. The failure mode is **staleness behind shipped work** — docs that were true when written and were not updated when M4–M7 landed hours later. Every item below was re-verified at line level for this review:

| Location | Stale statement | Reality |
|---|---|---|
| `docs/PRODUCT.md:81` | pack holds 70 ask + 77 report = 147 | 155 rules: 80 allow / 66 ask / 9 deny |
| `docs/ARCHITECTURE.md:366` | "152 rules today; 73 stop the user; floor answers 6 of the 61 questions" | 155; floor answers 6 of the **66** questions (`docs/POLICY.md:734` has it right) |
| `docs/DIRECTION.md:321` | "What does not exist yet is … the quarantine flow as an interactive state" | M4 shipped it 2026-08-31; e2e T12 exercises it |
| `docs/MILESTONES.md:243` | "74 scenarios are blocked on observables today" | ledger no longer maintains a blocker count after the sensor shipped |
| `README.md:286` | "No delete and no rename event. The schema has no shape for them yet" | `crates/af-core/src/event.rs:248,256` define both (sensor-emitted); the *external observer* path is the actual gap — the sentence is wrong about the schema, right about the monitor |
| `docs/DECISIONS.md:174` | "L0 is recommended and unbuilt" | ML shipped L1/L2 and the floor; L0 remains unbuilt but the entry was never superseded |
| `docs/PRODUCT.md` §5 narrative | "Six of the questions … 1.0×" | floor bench is 0.98×–1.07×; "1.0×" rounds optimistically |

Governance strengths: the decision log is dated, evidence-named, and newest-wins; the milestone ledger records gates with committed measurements (M6 entry: "361 tests green (26 suites), e2e 54/54" — true then, not true now, which itself demonstrates why gates need CI); as-built/as-directed separation held under four hostile lenses. Governance weaknesses: the doc set is written for research agents, not adopters (no newcomer path, no task index); `ARCHITECTURE-OVERVIEW.html` is a tracked artifact 14 hours stale against a major ship and unreviewed; no CONTRIBUTING means the (genuinely good) rule-change process — in-file tests, budget compliance, `cargo test -p af-policy` — is invisible to outsiders; and the `.rohrpost` incident (§2.5) shows the ticketing governance losing its newest open item during a read-only review. **Recommendation adopted into §14: generated (not hand-written) counts, a docs drift check in CI, and a newcomer path.**

---

## 8. Rohrpost ticket audit — complete

**State at HEAD (re-read by this review):** `.rohrpost/tickets.jsonl` holds 9 tickets; `.rohrpost/log.jsonl` holds 33 events; `rp doctor` reports all structural checks ok (unique IDs, references, cycles, snapshot fold, gitattributes union-merge); `rp stats`: cold fold 0.793 ms. `git` shows `.rohrpost` history committed normally through M7.

**The ladder (all `done`, epic `b0n24k` open):**

| Ticket | Milestone | Exit-gate measurement (from the ledger) |
|---|---|---|
| `[af-1]` M1 | Bypass harness | matrix of held/seen/silent per filter mode; benign corpus quiet |
| `[af-2]` M2 | In-process sensor | 98% (1205/1231) corpus actions invisible to argv; sensor ×1.13–1.29 over product; sensor never decides |
| `[af-3]` M3 | Agent identity | precision 1.000 / recall 0.957 on 53 fixtures; escape facts flagged |
| `[af-4]` ML | Landlock floor | 6 of 61→66 questions kernel-answered; 0.98×–1.03× bench; e2e K1–K8 |
| `[af-5]` M4 | Tamper + quarantine | 4/4 seeded techniques, 3 identical runs; negative test refused the detach rule; benign corpus zero quarantines |
| `[af-6]` M5 | Correlation | 2 quarantine + 1 report rule; benign zero firings; write-compare refused with numbers (30/session) |
| `[af-7]` M6 | Telemetry + alpha | 361 tests, e2e 54/54 *at the time*, benign zero in three modes, sample lifecycle test, no backend exists |
| `[af-8]` M7 | Windows survey | two sensor/observer decisions; "Windows has no unprivileged equivalent of seccomp+Landlock"; "Nothing here was run" |

**Findings:**

1. **The forward queue is empty.** `rp ready` → "No actionable work. The tube is empty." Every ticket is `done`; the epic is open with nothing under it. The project's own governance law ("work is ticketed in `.rohrpost`; one ticket per milestone with its exit gate in the body") currently has **no next milestone, no owner, no plan of record** — the ladder ends at M7 with the directed-but-unbuilt work (attach mode, live correlation, Windows spike, telemetry backend, enterprise tier) unticketed.
2. **The af-9 anomaly (the promised follow-up that does not exist).** HEAD `c7ca6f0`'s message says "…and file it as af-9" and its body says "filed as AF-an4nm7." The commit contains no `.rohrpost` change. The uncommitted ticket existed at 22:41 (wave-1 transcript; §2.5) and was destroyed before 23:31 by an unattributable revert. **Net effect: the repository's own commit message promises follow-up work — "trace path as a rule-visible B.5-style fact, tamper rules for trace writes, history erasure and transcript tampering with negative tests" — that is now tracked nowhere except a review transcript.** This is the concrete, evidenced instance of "missing promised follow-up" requested by this review's charter: not conjecture about lost content, but the proven absence of a ticket that the HEAD commit message claims exists.
3. **Ledger/queue health otherwise clean:** parsed events match, no cycles, snapshot folds. The archive and shadow directories are untracked and empty.

**Required actions (P0-8 / remediation Phase A):** re-create the af-9 ticket from the surviving transcript text; make the commit message and the repository agree (follow-up commit or amended ticket); add a pre-review hash snapshot of `.rohrpost` (the stage-2 verification already modeled this) and investigate the cause before running another agent workflow against the repo.

---

## 9. Competitor landscape

Reconstructed from the two independent wave-1 market studies (finals lost; raw scrapes retained) and **live primary-source re-verification by the stage-2 market cross-check (2026-08-31/09-01)**. Confidence labels are the cross-check's; this reviewer sampled, not re-scraped, the sources. One correction was adopted (there is no "Tessl Safehouse"; the tool is Agent Safehouse, independent OSS, Tessl only covered it), one rumor dropped (Cisco–SentinelOne acquisition talk: unverified), several category errors refiled (GuardAgent, LlamaFirewall, Infisical's "Agent Sentinel," Microsoft RAMPART, Contrast RASP).

### 9.1 Direct competitors (same job: local, vendor-neutral supervision of agent + execution tree, deterministic policy, intervention)

| Project | What it ships | Boundary / privilege | Delta vs Agent Firewall | Confidence |
|---|---|---|---|---|
| **ActPlane** (eunomia-bpf) — github.com/eunomia-bpf/ActPlane | eBPF/BPF-LSM information-flow policy engine; lineage-scoped rules ("no codex may run git push"); kill/block/notify; corrective feedback to the agent via hooks/MCP | root / CAP_BPF; Linux 5.10/6.1+ | Closest to AF's *enforcement* concept at kernel grade; needs root; no human interactive approval at the boundary; richer policy algebra; 95★, 397 commits, active daily, ATC'26 submission (arXiv 2606.25189) | High (README live-scraped) |
| **Rampart** (peg) — github.com/peg/rampart | allow/ask/deny at hooks/plugins/proxies; YAML policy, hot-reload; approvals; hash-chained audit; wrap/preload for non-native agents | user-space, cooperative, no root | Closest to AF's *product shape*; 10+ agent integrations; own threat model concedes it "does not see arbitrary syscalls … inside a process you already allowed" — exactly the gap AF's external tree supervision fills | High (README live) |
| **Prempti** (falcosecurity) — github.com/falcosecurity/prempti | Falco rule engine applied to agent **tool calls**; Allow/Deny/Ask; default ruleset; Claude Code only today | user-space service, tool-call boundary, no root | Brings a mature rule-feed ecosystem and approval UX to the tool-call layer; blind to the descendant process tree — AF's as-built core; experimental (May 2026) | High (Falco blog live) |
| **AgentWall** (agent-wall) — github.com/agent-wall/agent-wall | MCP proxy + plugin; pre-execution interception; human approval; execution trail for audit/replay | user-space, MCP/tool boundary | Matches policy+approval+replay at the tool layer; thin eval (14 tests) | High (arXiv 2605.16265 abstract; repo not deep-dived) |
| **AgentSight** (eunomia-bpf) — github.com/eunomia-bpf/agentsight | eBPF top/strace for agents; sessions, trees, file/net effects, TLS LLM capture, OTel export, replay | eBPF needs sudo (fallback without); Linux | The observability half, free, fast-shipping, ACM-published (DOI 10.1145/3766882.3767169); 613★, v1.0.30, Homebrew; no enforcement | High |

### 9.2 Near-direct and mechanism prior art

- **Sandlock** (multikernel) — github.com/multikernel/sandlock, arXiv 2605.26298 (ASPLOS'26 Agentic OS workshop). Unprivileged Landlock + seccomp-bpf + **seccomp user-notify with held syscalls** (`execve`, `connect`, `sendto`, `bind`, `openat` — child blocked until a `policy_fn` returns allow/deny/audit) + `pidfd_getfd`; explicit TOCTOU handling matching AF's own rule; COW filesystem, HTTP ACLs; Linux 6.12+. **This publishes AF's exact unprivileged mechanism stack with code and a workshop paper — the strongest single novelty invalidator.** Confidence: High (README + abstract live).
- **Microsoft Agent Governance Toolkit** — github.com/microsoft/agent-governance-toolkit. Governance SDK: Cedar/OPA/YAML policy, audit, identity (SPIFFE/DID), sandbox rings, Shadow AI discovery; plugins for Claude Code/Copilot. 6.2k★, 2,459 commits. Cooperative/library-level enforcement, not an OS boundary; more a future distribution channel or category mindshare owner than a like-for-like rival. Confidence: High.
- **Ona Veto** — ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox, ona.com/docs/ona/guardrails/veto. BPF-LSM content-hash exec denylist, pre-execution, rename-proof; documents Claude Code escaping its own path-based denylist and sandbox — strong public evidence for AF's threat thesis; commercial early access inside Ona's cloud environments only. Confidence: High.
- **cplt** (navikt, Norwegian public sector) — github.com/navikt/cplt. Landlock sandbox wrapper across Copilot/OpenCode/Gemini/Antigravity/Pi/Claude Code/Shell; free, vendor-neutral, no policy layer. Public-sector proof of appetite. Confidence: Medium-High (gist + README snippet; not deep-dived).
- **Dogwood** (AWS) — github.com/dogwood-policy/dogwood. Open governance *language* (Cedar-compatible, temporal conditions over recent events) for agent tools — a possible policy standard AF rules could compile to. Confidence: High.
- **aflock** (signed policy artifacts, "package-lock.json for agents"), **AgentSentinel** (m4p1e; eBPF intercept-and-audit, arXiv 2509.07764 — dormant, 1 commit, Aug 2025), **Claw Patrol** (Deno) — leads, not live threats. Confidence: Medium.

### 9.3 Substitutes (isolation instead of supervision)

- **Codex CLI sandbox** (learn.chatgpt.com/docs/sandboxing): default-on OS sandbox (Seatbelt; bubblewrap+Landlock on Linux; native Windows tokens), `read-only`/`workspace-write`/`danger-full-access`, approval policies, prefix rules, LLM auto-review. Free, cross-platform, zero install. Confidence: High.
- **Claude Code sandbox + `@anthropic-ai/sandbox-runtime`** (code.claude.com/docs/en/sandboxing; github.com/anthropic-experimental/sandbox-runtime): OS-enforced fs+network for Bash **and all children**, network proxy with domain allowlists, credential masking with proxy re-injection (including AWS SigV4 re-signing), protected paths, optional seccomp filter; open-sourced `srt` engine (beta). The single biggest build-vs-buy pressure for Claude shops. Confidence: High.
- **Docker Sandboxes** (docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely): microVM per agent, multi-agent, network ACLs, MCP gateway on roadmap. Strong "run unsupervised in a box" answer; heavy; no semantics. Plus the saturated long tail (E2B, microsandbox, Chamber, Agent Safehouse, hakoniwa, Trail of Bits devcontainer, gVisor MAGI, etc. — 50+ entries in the wincent "coding agent sandboxes 2026-05" gist). Confidence: High for Docker; Medium-High for the tail.
- **Enterprise runtime SaaS** (Lasso, Zenity, Operant, Invariant, Straiker, Lakera/Check Point, Prisma AIRS, SPLX): prompt/MCP/tool-call inspection platforms for fleets — different buyer, server-side; substitutes at the enterprise layer. Confidence: Medium-High.

### 9.4 Incumbents

- **CrowdStrike** — crowdstrike.com press release, RSA 2026 (Mar 23, 2026): "EDR AI Runtime Protection … captures the commands, scripts, file activity, and network connections of all applications … including agentic applications … trace activity to the originating process … isolating affected endpoints." **Directly falsifies any "EDR can't see agents" positioning**; carries an "unreleased features" disclaimer; enterprise sensor/console model. Confidence: High (press release verified).
- **SentinelOne** (acquired Prompt Security, Aug 5, 2025; "Prompt AI Agent Security" at RSAC 2026), **Cisco** (AI Defense runtime protections; DefenseClaw; Astrix acquisition), **Microsoft** (AGT + OS estate), **Falco/Sysdig ecosystem** (Prempti; the Falco rules feed is the incumbent version of AF's imagined feed), **Tetragon/KubeArmor/Tracee** (kernel enforcement with lineage selectors exists today; the *product* half — developer approval UX — is what nobody shipped). Confidence: High.

### 9.5 What actually survives as differentiation

**Drop these novelty claims (each is falsified):** first unprivileged Landlock+seccomp-notify supervisor (Sandlock); first kernel lineage-scoped deterministic policy (ActPlane/Tetragon); first Falco-style feed / allow-ask-deny for agents (Prempti/Rampart); first external agent observability (AgentSight); first proof that path-based controls fail (Ona Veto); first agent policy languages (Dogwood/AGT).

**Survives (verified absent in every project above):** external, unprivileged, **agent-cooperation-free supervision of the whole execution tree**, holding arbitrary descendants at exec/write/connect with no root; **interactive human approval at a descendant's exec boundary with the full provenance chain shown**; **threat-ledger-derived semantic rules** (`psql … DROP DATABASE` chain attribution); **replayable evidence with re-judgment**; **vendor neutrality by construction**; and the **interruption-budget methodology**. Honest counterweights: ActPlane is one release away from an ask-effect; eunomia could fuse AgentSight+ActPlane; Rampart could add an external sensor; CrowdStrike could productize agent policy; AGT could absorb the policy layer. The window is measured in quarters, and eunomia ships fast.

---

## 10. Product, UX, privacy, trust, open-source/commercial boundary, GTM, and likely ICP

### 10.1 Product and UX as shipped

The interactive product is a developer-laptop artifact: build from source (Rust, Linux, x86_64, kernel ≥5.13 for Landlock), then wrap every session (`agent-firewall run -- claude`). No shell completions, man page, brew/crates.io distribution, VS Code/hook integration, or agent-harness adapter (README admits: no agent log adapters). The approval UX itself is the best-executed surface (§4) — provenance-context prompts, all-matched rules, deny-safe everywhere — but its best feature (ask-with-context) is worthless exactly where the budget is (unattended runs), and its 120-second invisible tree-freeze on every question is a latent support burden. Known UX debt: no session-end intervention summary; no "what do I do now" doc (exit code 3, was anything executed?); no false-positive reporting path — remarkable for a product whose own kill criterion is "too many questions"; no log file (stderr is swallowed by agent UIs); Landlock floor friction (`ls ~` fails EACCES) trains `--landlock off`, the classic AV death spiral pre-announced.

### 10.2 Privacy and trust engineering — the strongest layer

The telemetry/consent architecture is best-in-class for the stage (double opt-in, five granular revocable scopes, inspectable/destroyable local outbox, redaction-first with negative tests, pseudonymization, baseline/absolute-time/env-values never sampled) and the no-exfiltration sentence is dependency-graph-true. Live findings that must be fixed before any distribution: `DATABASE_URL` userinfo captured raw into traces (`crates/af-monitor/src/procfs.rs:25` — allowlisted name without a secret marker); traces/consent/samples at umask-dependent 0644 on shared machines; redaction blind spots (JWT/PEM/base64) acceptable only while nothing leaves the machine; the claim is true but not enforced (no `cargo-deny` ban). The trust *infrastructure* is empty: no CI, no signing (57/57 unsigned commits), no SECURITY.md, no release process, placeholder repo URL. A security tool that watches every process, distributed as an unsigned tarball with no disclosure channel, is the supply-chain pattern it warns users about. **Order of operations is a hard gate: disclosure channel → signed release → distribution (P0-4, remediation Phase A).**

### 10.3 The open-source/commercial boundary — drawn in the wrong place

DIRECTION §9 opens the sensors/engine/basic rules and closes the corpus/feeds/research automation ("the value is the maintained rule feed," PRODUCT §4; "the runtime is the distribution channel"). Three falsifications from the review corpus: (1) the hard engineering is the open part anyone can take — Apache-2.0 lets ActPlane, CrowdStrike, or Microsoft embed it and attach their own feed; (2) rule feeds are cheap to fork, expensive to defend, and *paywalled detections are known holes to non-payers* — poison for exactly the paranoid audience that would adopt this; (3) the feed business requires telemetry scale the product's own decision log (2026-08-30) declares incompatible with its audience ("the audience most likely to install a security monitor is the audience most likely to refuse telemetry"), and no update channel, pack versioning, or signature exists — today "the feed" means "recompile." **Recommended redraw (P1-12): detections and runtime open forever; the control plane (fleet policy management, SIEM/audit export, consented ingestion, analyst tooling) closed. Sell the platform and the pipeline; give away the rules.** This should be a DECISIONS entry with the same evidence discipline as the technical calls.

### 10.4 GTM and the likely ICP

There is no ICP anywhere in the repository — the clearest single product gap (PRODUCT.md §4 defines a business model, never a buyer). The review corpus converges on one wedge supported by evidence:

**"Unattended Agent Guardrail" — deterministic guardrails + evidence-grade audit for coding agents that run with real credentials and no watching human (CI jobs, background/overnight agents, managed Linux dev VMs).** Why the evidence supports it: prompts are worthless at 3am, so the product's deny-safe fail-closed core is the right shape; the runner already wraps the agent, so integration is one line; the trace+replay record is the compliance artifact ("what did the agent do overnight — prove it"); the sandbox gap is structural (the Replit-class wipe happens *inside* an entitled container; sandboxes cannot read `psql` argv semantics or chain credential-read to egress); EDR agents don't fit ephemeral CI runners. ICP priority: (1) platform/DevEx engineering at AI-native companies (50–2,000 devs) after an agent incident — Director/VP buyer, developer-security/AI-governance budget class ($30–80k/yr deals); (2) security/DFIR needing agent-attack evidence capture (retainer class); (3) regulated shops needing an agent-activity audit artifact (navikt's cplt proves the appetite, for the free layer). Anti-ICP: solo macOS/Windows devs; "we already bought the EDR module" orgs; never-telemetry teams. Pricing hypotheses to falsify (not defend): OSS free; Team $20/dev/mo (Snyk ≈$25, GHAS ≈$49 anchors); Enterprise $40–60/dev/mo + $25–50k/yr floor; DFIR $15–25k/yr. The interactive developer product remains the demo, the on-ramp, and the rule-authoring environment — not the business.

---

## 11. The strongest case that this is an AI-psychosis project

Stated at full strength, as its best advocate would, with each argument graded **fatal flaw** (kills the project as scoped), **alpha limit** (true today, fixable or contract-narrowable), or **unknown** (evidence absent), and with the evidence that would refute each. "AI psychosis" here means: an agent-built (and partly agent-reviewed) edifice whose measured demonstrations keep getting narrated into claims — security boundary, threat-intelligence moat, category-defining company — that the evidence does not carry.

### 11.1 Technical impossibility arguments

**P1. A user-space same-uid monitor cannot be a boundary against a hostile same-uid peer — a category error, not a bug. [FATAL as scoped; fixable only by re-architecture]** The monitor and the target share authority. The target can `ptrace` the monitor, write its memory via `process_vm_writev` or `/proc/<pid>/mem`, send it `pidfd_send_signal`, `pidfd_getfd` its descriptors, or simply SIGKILL it from outside the tree — the shipped filter holds only `kill`/`tkill`/`tgkill` aimed at the monitor (`seccomp.rs:311-313`) and yama=0 is a supported posture (`caps.rs:189`). The "tamper signal" is a scripted-kill tripwire, not integrity. *Refutation evidence:* a hostile same-UID harness (ptrace/process_vm_writev//proc-mem/pidfd routes, external SIGKILL) run under Yama 0–3 showing every route denied by an independent boundary, or the session terminated with durable evidence naming the route, or a shipped separate-UID/privileged supervisor with kernel policy. Absent that, the only honest refutation is narrowing the claim.

**P2. io_uring is a measured complete bypass — the project's own harness proved the "firewall" silently watches nothing while everything happens. [FATAL to any boundary claim on stock hosts; closable by deny + compatibility measurement]** `IORING_OP_OPENAT` with write intent, zero events, every filter mode (`research/bypass/FINDINGS.md:86-88`). An agent can read credentials, alter files, and do network I/O while the action stream is silent. The docs' mitigations are future work; a sysctl check is posture. *Refutation:* an always-on deny of `io_uring_setup/enter` for agent trees with a measured benign-compatibility set (EXP-T1), or kernel-side ring enforcement with tests. Until then every security sentence must carry the gap.

**P3. The TOCTOU soundness rule proves the policy's central semantic object — the path — is unusable for authorization. [ALPHA LIMIT, held honestly]** The supervisor's path differed from the kernel's 47.6% of the time under two threads (`DETECTION-RESEARCH.md:71`). The code honors "never allow on a judged path," but the policy model is predominantly path/name/content-shaped, and "no rule matched ⇒ allow" is a path-influenced default. A hostile program can choose the race. *Refutation:* a type-level invariant (pointer-derived facts unable to reach allow paths) plus mutation tests, or object-based authorization (fanotify permission FDs, brokered opens).

**P4. Landlock is a floor wearing a boundary's clothes. [ALPHA LIMIT]** No argv/hostname/SQL/chmod/ioctl mediation; exec-from-anonymous-fd allowed; the work tree and `/tmp`/`/var/tmp`/`/var/cache` fully writable (`landlock.rs:358`) — a credential file created under the work tree is unprotected by the home carve-out; irrevocable per session, training `--landlock off`. *Refutation:* a published set-theoretic contract of exactly what the floor guarantees, tested across symlinks, bind mounts, renamed paths, worktree-under-home — and marketing that never exceeds it.

**P5. The mechanism is already published. [FATAL to novelty claims; not fatal to the product]** Sandlock (arXiv 2605.26298, ASPLOS'26 workshop) ships unprivileged Landlock + seccomp-notify holds + pidfd_getfd with a `policy_fn` callback and explicit TOCTOU handling. ActPlane ships kernel-grade lineage enforcement. AgentSight ships the observability. Whatever the repo believed about its uniqueness in August, the mechanism moat is zero as of this review. *Refutation (of the moat-collapse consequence):* sustained shipping of the bundle + UX differentiation faster than eunomia fuses its two projects.

### 11.2 Unnecessary-category arguments

**P6. The vendors already solved the 80% case, free and default-on. [FATAL to the consumer thesis; the enterprise/wedge thesis survives]** Codex CLI sandboxes by default on all three OSes; Claude Code sandboxes Bash and all children with credential masking and proxy re-injection; Docker ships microVM-per-agent with network ACLs; CrowdStrike traces agentic apps to the originating process on a fleet it already owns. The interactive laptop product competes with free, default-on, cross-platform, zero-install alternatives on their home turf (macOS/Windows) while itself being Linux/x86_64/build-from-source. *Refutation:* evidence that ≥20% of corpus incidents occur in harness-external descendants vendor sandboxes structurally cannot attribute (the corpus hints; the stat was never derived), or procurement language at ≥3 recognizable orgs demanding vendor-neutral audit.

**P7. The buyer is not the user. [ALPHA LIMIT of the current shape]** The user is a developer on a Linux laptop; the budget is in platform/security orgs that need headless policy, central management, Windows coverage, SIEM export, and tamper-protected evidence — none shipped, all directed. The product's best feature (ask-with-provenance) requires a watching human; the humans who want always-on guardrails are precisely those running agents unattended. *Refutation:* the `guard --ci` mode plus pilot conversions (G1/G2 gates, §15).

**P8. The wrong-control argument cuts the other way at the margin. [UNKNOWN, contested]** AF's thesis is "sandboxes are too coarse, prompts too blind" — asserted, never measured against 2026 sandbox UX (Codex `workspace-write` is usable; Claude's credential masking is sophisticated). If a microVM + the vendor's own permission system answers 95% of the pain at 5% of the friction, the semantic middle is a niche of a niche. *Refutation:* the A/B "3am demo" experiment (time-to-root-cause with vendor logs vs. AF trace+replay) and the publishable harness-external-descendant stat.

### 11.3 Adoption-economics arguments

**P9. ptrace cost makes the daily-driver story unsupportable. [ALPHA LIMIT, possibly fatal to interactive daily use]** The repo's own numbers: ~10× on file-heavy work under ptrace alone (`af-monitor/src/lib.rs:113-116`); product 11.0× and product+sensor 12.5× on W2 (`inprocess/FINDINGS.md:145-146`); filter adds 1.16–1.92×; a coding-agent day *is* builds and npm installs. Every number is single-machine, synthetic-workload, loaded-host. *Refutation:* p95 real-workload (cargo build / npm ci / docker build) overhead <2× across ≥5 distros, published honestly (EXP-T4) — or the Landlock ABI grows network rights and the 1.0× floor absorbs most ptrace duties.

**P10. "Quiet is the feature" is proven on a 28-second synthetic corpus. [ALPHA LIMIT]** 66 of 155 rules ask; the quiet gate is a scripted git/cargo/npm session; one on-disk benign run mode contains a quarantine FAIL (`benign-summary.txt:4`); `count-rules.py` — the pack/floor drift guard — exits 1 today; real dev days (docker, terraform, kubectl, venvs, node-gyp) are unmeasured. Prompt fatigue is the acknowledged category killer, and the mitigation evidence is thin. *Refutation:* the 10-dev, ≥10-real-project, two-week quiet study hitting <2 questions/day median, <20% floor-off, <2× build time (EXP-T5).

**P11. The business model contradicts the product's own decision log. [FATAL to the feed-as-moat plan]** The moat requires telemetry scale; telemetry is opt-in-off by design; the 2026-08-30 decision entry states the installing audience refuses telemetry; there is no backend, no consent scale, and the bootstrap corpus is public to every competitor. What compounds today is the founder's research discipline — a brand/services moat, not a data moat. *Refutation:* ≥30% contract-opt-in telemetry consent among paid seats (G3) — i.e., B2B consent solving what consumer consent cannot.

### 11.4 Moat-failure arguments

**P12. Commoditized on every flank. [ALPHA LIMIT — the window is quarters, not years]** Below: free vendor sandboxes. Beside: Rampart/Prempti/AgentWall at the tool layer, cplt free at the wrapper layer. Above: ActPlane at the kernel, CrowdStrike/SentinelOne on the fleet, AGT in governance, Sandlock in the literature. What remains — the bundle + approval UX + budget methodology — is real but is a *quality-of-question* improvement, the hardest kind to price, and single-maintainer. *Refutation:* a competitor-analysis cadence that shows the bundle still unshipped in 12 months while AF's wedge pilots convert.

**P13. The trust assets are spendable once. [ALPHA LIMIT, self-inflicted risk]** The honesty brand (alpha banner, limits-as-threat-model, bypass matrix) is the project's differentiator with security buyers. One launch post claiming boundary-grade protection, contradicted by the project's own bypass matrix, ends it. Meanwhile the repo's actual gates (e2e red-ish, count-rules red, no CI, unsigned everything, the af-9 commit-message anomaly) already strain the "disciplined" narrative under due diligence. *Refutation:* Phase A green plus the overclaim-guardrail checklist (§14) applied to every public sentence.

**P14. Zero users, zero distribution, single maintainer, four-day-old history. [ALPHA LIMIT]** 57 commits over four days, one author, no external contribution, no CI, no release. Every claim about compounding loops rests on an adoption that does not exist. *Refutation:* first signed release, first external contributor, first pilot — each is a Phase A–C gate.

### 11.5 The psychosis diagnosis, weighed

The strongest honest version of the accusation: **a system built by agents, reviewed by agents, narrated into a security category whose central guarantee (a boundary) its own measurements refute, targeting a customer its own decision log says will not pay for the moat as designed.** The refutation the evidence actually supports: the project *measured itself into* every one of these limits — the io_uring zero, the 47.6% race, the 8.8× rejection, the budget refusals are all *its own* findings, published against its own interest; the as-built/as-directed line held under four hostile lenses; nothing directed was found promoted to built. That is the opposite of psychosis — it is the behavior of a research program. The psychotic risk is not in the artifact; it is in the *narrative step* from "measured alpha wrapper" to "firewall company," which this review exists to prevent. **Verdict: not psychosis — a good research project wearing a product thesis two sizes too big.** The distinction is actionable: shrink the claims (P0-5), close or name the two structural bypasses (P0-6/P0-7), and let the wedge evidence decide the company question (§15–§16).

---

## 12. The strongest positive thesis, the assets worth preserving, and their limits

### 12.1 The thesis

**Agent Firewall is the most measured, honest, and discipline-governed pre-product program in the AI-agent runtime-security category, and the only reviewed project that ships end-to-end: provenance-attributed deterministic policy over a whole execution tree, stateful session rules, an interruption budget with teeth, fail-closed quarantine, and replayable evidence — a bundle none of the identified competitors ships together. Its weaknesses are exactly disjoint from the needs of one wedge — unattended coding agents with real credentials — where prompts are irrelevant, fail-closed is desired, wrapping is natural, and the evidence trail is the product. The strongest defensible claim is not "security boundary" but: a differentiated, honestly-scoped guardrail-and-evidence runtime for cooperative-but-dangerous agents, plus a reusable research methodology, one measured demonstration away from demand proof.** That last clause is the thesis's own limit: zero adoption, no CI, no signed release, gates not all green today.

### 12.2 Assets worth preserving (each with its exact limit)

- **A1. The measurement culture** — every number traceable to runnable code; the budget overruled severity twice with numbers; null results honored. *Limit:* one machine, synthetic workloads, some gates now red. *Protect by:* CI + multi-distro bench (P0-2, P1-2).
- **A2. The bypass harness and matrix** — adversarial self-measurement as a standing, regenerable asset; caught evidence-erasure the docs didn't know about. *Limit:* one host posture; the matrix is a scope statement, not a guarantee; three more structural routes (inherited fds, pidfd, monitor attach) are not yet in it. *Protect by:* publish per release; extend to the hostile harness (EXP-T2/T3).
- **A3. The threat-research pipeline** — 90 incidents → 255 scenarios → checkable ledger → budget-gated human-approved rules; live-verified source fidelity. *Limit:* corpus is public; counts ≠ prevalence; slow by design. *Protect by:* publish the derived harness-external-descendant statistic; keep `check.py` a release gate.
- **A4. The shipped, test-gated runtime** — 9 crates, 361 tests, 672 policy tests, quarantine as a first-class state, deny-safe approval, replay parity as a design constraint. *Limit:* yellow gates, no CI, single maintainer. *Protect by:* Phase A.
- **A5. The telemetry/consent architecture** — best-in-class trust engineering, no-exfiltration provable from the dependency graph. *Limit:* true-not-enforced; DATABASE_URL gap; 0644 perms. *Protect by:* cargo-deny ban + P0-4 fixes.
- **A6. The kernel floor ("quiet by construction")** — six questions answered at 0.98×–1.07× with explained denials. *Limit:* fixed deny allowlist, small count, irrevocable, `--landlock off` trained by friction. *Protect by:* the Landlock contract test matrix + ABI watch (P1-7).
- **A7. Reusable IP even under pivot:** the incident→scenario→observable→rule pipeline as an open dataset/eval standard; the bypass-matrix methodology as a category benchmark; the TOCTOU soundness rule as a publishable design law for every seccomp-notify supervisor; the normalized event schema as a neutral interchange format; the sensor contract ("a sensor is not a boundary") as instrumentation discipline.

### 12.3 The limits of the thesis

Every positive claim above is one-host, zero-adoption, pre-release. The differentiation is a bundle position in a market where a fast-moving team (eunomia) owns the two nearest projects and incumbents have announced; the wedge is inferred from incident shapes, not from a signed pilot; and the trust brand, while real, has never survived contact with an external user base. The thesis converts to fact only through the H1–H7 gates of the remediation plan (§14) — and it explicitly does **not** promise the privileged boundary tier.

---

## 13. Prioritized findings table

Impact = decision-level effect. Effort: S ≤ 2 days, M ≤ 1 week, L 2–3 weeks (repo convention). Owner types: M = maintainer; SE = security engineer; PE = platform engineer; F = founder (sales/BD); C = community/contractor.

| ID | Finding | Evidence (verified) | Impact | Effort | Owner | Depends | Acceptance gate (measurable) |
|---|---|---|---|---|---|---|---|
| **P0-1** | e2e gate not green: T8 reproducibly fails, T11 flaky (54/54 recorded at M6; 52/54 and 53/54 in two review runs) | `tests/e2e.sh` runs; M6 ledger `docs/MILESTONES.md:266` | Every "tested" claim rests on a red-ish gate | S | M | — | 54/54 in 20/20 consecutive CI runs |
| **P0-2** | No CI; all gates enforced by individual discipline | no `.github`/`.gitlab`; e2e header "for a person or a continuous-integration job" | Claims unenforced; flake invisible | S | M | — | Required checks block a red synthetic PR |
| **P0-3** | Number hygiene: stale counts (147/152 vs 155), `count-rules.py` exit 1 (3 unclassified correlation rules), on-disk benign FAIL line | `docs/PRODUCT.md:81`, `docs/ARCHITECTURE.md:366`, `research/spikes/landlock/tests/count-rules.py`, `research/bypass/results/benign-summary.txt:4` | Due-diligence credibility; "quiet" narrative | S | M | P0-2 | `count-rules.py` exit 0; no stale count in docs; regenerated corpus summary with zero FAIL |
| **P0-4** | Trust infrastructure absent: no SECURITY.md, no signing (57/57 unsigned), no release process, 0644 traces/consent/samples, `DATABASE_URL` userinfo raw in traces, placeholder repo URL | `git log %G?`; `procfs.rs:25`; `Cargo.toml:23`; stage-2 trust review | Blocks all external distribution safely | M | M | — | Dry-run signed tarball verifies on a second machine; `cargo deny` green; perms 0600 asserted in tests; masked userinfo in no fixture |
| **P0-5** | Threat-model overclaim risk: product name + §1 framing vs. measured boundary (io_uring, same-user monitor, tree≠world) | `research/bypass/FINDINGS.md:86-88`; `seccomp.rs:311-313,43`; README limits | One overclaim spends the honesty asset permanently | M | M | P0-3 | Adversarial doc pass (2 independent reviewers) finds zero claims exceeding the matrix |
| **P0-6** | io_uring complete bypass, unmitigated on stock hosts | `FINDINGS.md:86-88`; README:289-293 | Loudest technical kill criterion | M | M | P0-2 | Compatibility matrix committed; decision recorded (default-deny with measured breakage, or host-requirement + report) |
| **P0-7** | In-tree inherited/live descriptors bypass open/connect observation points (launcher vector closed by std `Command`; SCM_RIGHTS open) | stage-2 cross-check §6.4; tracer launch path | Structural bypass of the file/network story | M | SE | P0-5 | Hostile-parent fixture: every pre-opened capability closed or named; SCM_RIGHTS documented out-of-scope |
| **P0-8** | Rohrpost integrity incident: uncommitted af-9 destroyed in review window; HEAD commit message promises a ticket the commit lacks; forward queue empty | §2.5, §8; `git show c7ca6f0`; transcripts; mtimes 22:55:34 | Audit integrity; promised follow-up lost | S | M | — | af-9 re-created from transcript; cause documented in DECISIONS; pre-workflow `.rohrpost` hash snapshot standard |
| **P1-1** | No headless mode: interactive `/dev/tty` product only; `--approve` is all-or-nothing | `crates/af-cli/src/cli.rs` approve modes | The evidence-supported wedge cannot ship | L | M | P0-1/2 | `guard --ci` + JSON export; 30-day self-pilot: zero false-denies; every deny maps to a rule id |
| **P1-2** | Single-host evidence base; results gitignored; no replication | `.gitignore:35`; all FINDINGS | No claim survives a second machine today | M | M | P0-2 | Quiet+perf matrix regenerated on ≥2 distros (≥5 by day 90), committed |
| **P1-3** | Perf unmeasured on real workloads; 10×/11×/12.5× synthetic file-heavy | `lib.rs:113-116`; `inprocess/FINDINGS.md:145-146` | Daily-driver + CI-wrapper viability unknown | M | M | P1-2 | Published p50/p95 for cargo/npm/docker builds vs baseline vs Codex sandbox, 5 real repos |
| **P1-4** | Identity/correlation/sensor facts unconsumed by any rule; synthetic fixtures only | grep over packs; M3 ledger | Shipped subsystems with no product yield | L | M | P1-1 | Real-agent corpus (≥3 agents installed); precision/recall published; 1 budget-compliant identity rule |
| **P1-5** | Quiet unproven at real diversity; Landlock-off training risk | `benign-summary.txt`; PRODUCT §5 | Category-killer risk unmeasured | M | M | P1-4 | 10 devs / ≥10 projects / 2 weeks: <2 questions/day median, <20% floor-off, <2× build p95 |
| **P1-6** | Monitor hardening absent (PR_SET_DUMPABLE, pidfd_send_signal hold, hostile harness) | `seccomp.rs:43,311-313` | Tamper story overstates integrity | L | SE | P0-5 | Hostile same-UID matrix under Yama 0–3: every route denied/sensed/named; no benign firings |
| **P1-7** | Landlock contract unpublished; `/tmp`+worktree credential gap | `landlock.rs:358,594` | Floor claims exceed guarantees | M | SE | P0-5 | Set-theoretic contract + symlink/bind-mount/worktree-under-`/tmp` tests; `.ssh`-under-`/tmp` denied and explained |
| **P1-8** | TOCTOU invariant by convention only | `DETECTION-RESEARCH.md:71,217` | Future allow-path drift risk | M | SE | P0-5 | Type-level newtype; doctest: allow-on-advisory-path no longer compiles; race mutation tests |
| **P1-9** | UX supportability gaps (no session summary, no incident doc, no FP report path, no log, invisible 120s freeze) | stage-2 trust review §6–7 | Adoption and support impossible | M | M | P0-4 | Each feature CLI-tested; INCIDENTS.md answers "exit 3 — what ran?" |
| **P1-10** | No ICP, no market evidence | absence in PRODUCT.md; §9–10 | Company thesis untested | M | F | — | 25 interviews coded; 3am-demo booking rate; WTP gate offered (§15) |
| **P1-11** | No distribution artifacts | no tags/releases/completions/man | Adoption friction maximal | M | M | P0-4 | v0.2.0 signed tag + install channel; 5 external testers reach a guarded session <10 min |
| **P1-12** | Open-core boundary drawn wrong (feed private); contradicts trust + decision log | DIRECTION §9; DECISIONS 2026-08-30 | Corrosive to the defensible moat | S | F | P1-10 | DECISIONS entry redrawing the line: detections open, control plane closed |
| **P2-1** | Control plane absent (central policy, aggregation, SIEM) | DIRECTION §10 directed-only | Enterprise buyer prerequisite | L | PE | GO gate | 3 pilots run centrally-managed policy 30 days |
| **P2-2** | No signed rule-pack channel; builtin pack compiled in | `builtin.rs` include_str! | Feed business impossible; enterprise integrity absent | M | PE | P2-1 | Pack update ships without binary release; tampered pack fails verification |
| **P2-3** | Privileged boundary tier unbuilt (F1/F2/F3 kernel-grade closure) | §5.3 | Hostile-peer claims impossible below this tier | L | SE | GO gate | Prototype + hostile matrix re-run: routes denied or costed in FINDINGS |
| **P2-4** | Live correlation unbuilt (post-hoc only) | DECISIONS 2026-08-31 | Findings can't stop the producing action | L | M | pilot demand | A live discrepancy holds pre-completion; benign corpus still quiet |
| **P2-5** | aarch64 filter absent; foreign ABIs exec-only | `seccomp.rs:336,393` | ARM dev machines outside the claim | M | SE | P1-2 | arm64 CI runner filter tests green; unsupported ABI labeled "exec-only," never "protected" |
| **P2-6** | Attach mode directed, unbuilt, unmeasured | DIRECTION §11 | "Works with agents you didn't launch" unsupported | M | SE | P1-6 | Yama 0–3 / PID-reuse / multithread matrix; feature gated or formally killed in DECISIONS |
| **P2-7** | Windows sensor spike unanswered (8 measured questions exist) | M7 ledger; windows-notes FINDINGS | Cross-platform direction uncosted | M | SE | ICP pull | Spike report with measurements, or a committed Linux-only decision |
| **P2-8** | Telemetry consent v2 undesigned (blind spots unnamed for any future backend) | stage-2 trust §3 | Trust rot when a backend lands | M | M | P0-4 | Design doc reviewed by 2 external privacy-literate reviewers; cargo-deny still green |
| **P3-1** | Docs for agents not adopters; no newcomer path; HTML overview stale | §7 | Friction for every external reader | S | C | P0-3 | 3 external readers reach "first rule written" unaided |
| **P3-2** | Name/trademark: "Agent Firewall" generic; near-collisions (aflock, agent-sentinel) | §9 | Weak trademark; pre-GTM search needed | S | F | GO gate | Trademark search + entity decision documented |
| **P3-3** | Dependency/supply-chain audit never run | §2.3 | Secondary but real for a security product | S | C | P0-4 | `cargo audit` + `cargo-deny` advisories green in CI |

---

## 14. Remediation and productization plan

Estimates are **hypotheses to be falsified by the gates, not promises**; sizes use repo convention (S ≤ 2 days, M ≤ 1 week, L 2–3 weeks). Standing law per project rules: every rule change runs `cargo test -p af-policy` with its negative test in-file and re-runs the benign corpus; every gate is a measurement committed next to runnable code; as-built/as-directed separation holds; research agents never publish production rules.

**Narrow product definition (v1 commercial wedge):** "Unattended Agent Guardrail" — a Linux launch wrapper for coding agents that run with real credentials and no watching human (CI jobs, background/overnight agents, managed Linux dev VMs). Deterministic pre-call denial (exec stop + selected syscall holds), conservative Landlock credential floor, provenance-attributed trace/audit export, tamper/quarantine sensing with fail-closed defaults, weekly rule pack from the public incident pipeline. **No interactive prompts.** Explicitly not: a sandbox replacement, host EDR, hostile-peer protection, io_uring coverage (until EXP-T1), inherited-capability coverage, non-x86_64 ABI coverage. Positioning line (the only one marketing may use until the matrix widens it): *"Deterministic guardrails and evidence-grade audit for autonomous coding agents — neutral across agent vendors, local-first, no root."*

### Days 0–30 — Phase A: "Make the record trustworthy" (P0)

| # | Task | Size | Gate |
|---|---|---|---|
| A1 | Fix `af-monitor` flake deterministically (sync, not sleep-tuning) | S | workspace tests green 20/20 consecutive CI runs |
| A2 | Fix e2e T8 (+T11 race) — assertions, not events | S | e2e 54/54 × 10 consecutive CI runs |
| A3 | CI: fmt, clippy, test, e2e, quiet-check, `check.py`, `policy test`; `cargo test -p af-policy` required for `policies/**` | S | red synthetic PR blocked |
| A4 | Reconcile all counts to 155 (80/66/9); classify/fix 3 correlation rules in `count-rules.py`; regenerate benign summary | S | `count-rules.py` exit 0; zero stale counts; no FAIL line |
| A5 | SECURITY.md + FP/FN report path; signed commits; minisign release signing; `cargo-deny` (af-telemetry network ban) + `cargo auditable` | M | signed dry-run verifies off-machine; `cargo deny` green; no-network claim CI-enforced |
| A6 | 0600 default for traces/consent/outbox; mask `DATABASE_URL` userinfo at capture | S | tests assert mode 0600 + masked userinfo |
| A7 | Threat-model statement (launch-mode, cooperative/accidental, tree-local, x86_64, not-hostile-peer) in README §1 + ARCHITECTURE §0 + banner + pitch rules (forbidden/required phrasing table) | M | 2-reviewer adversarial pass: zero overclaims |
| A8 | **EXP-T1**: io_uring deny compatibility corpus + 5 real workloads under deny | M | matrix + FINDINGS committed; default-deny decision (with breakage list) or host-requirement posture recorded |
| A9 | Launch fd hygiene: close inherited fds >2 via `close_range`; O_CLOEXEC audit; hostile-parent fixture | M | every pre-opened capability closed or named; SCM_RIGHTS out-of-scope in threat model |
| A10 | Rohrpost integrity: re-create af-9; reconcile commit message; adopt pre-review hash snapshot | S | DECISIONS entry states cause + preventive rule |

**Phase A exit:** all gates green ×20 CI runs; signed dry-run verified; io_uring decision recorded with numbers; no external users, no distribution, no marketing.

### Days 31–60 — Phase B: "Close the named gaps; build the wedge; gather market evidence" (P1; ≤$25k)

B1 `guard --ci` headless + JSON summary + exit-code contract (L; gate: 30-day self-pilot, zero merge-blocking false denies, SIEM-shaped summary) · B2 io_uring enforcement per A8 (M; benign corpus unchanged) · B3 monitor hardening + hostile same-UID harness under Yama 0–3 (L; matrix published: every route denied/sensed/named) · B4 Landlock contract + credential-floor extension incl. `.ssh`/`.aws` under work tree and `/tmp` (M; contract doc + tests; corpus quiet) · B5 TOCTOU type-level invariant (M; allow-on-advisory-path no longer compiles; race mutation tests) · B6 multi-distro bench ≥2 distros now / ≥5 by day 90 (M; committed matrix) · B7 perf bake-off: cargo/npm/docker × 5 real repos vs baseline vs Codex sandbox (M; published p50/p95 — honesty is the marketing) · B8 real-agent corpus ≥3 agents, identity P/R re-measured, ≥10 real sessions (L) · B9 UX batch: session-end summary, monitor-death warning ("trace may be truncated; treat as unverified"), timeout countdown, `doctor --json`, INCIDENTS.md (M) · B10 market: 25 problem interviews, 3am-demo landing page + video, install-friction test (10 external Linux devs, target <10 min), 5 CISO incumbent-gravity conversations (M; interview grid with named owner + budget line y/n).

### Days 61–90 — Phase C: "First external pilots; the go/pivot/stop decision"

C1 three external CI pilots ×30 days (gate: ≥1 real catch/near-miss across cohort; 0 merge-blocking false denies; <1 h/mo ops) · C2 WTP gate at $20/dev/mo list (≥3 accept ⇒ GO signal; 0/30 ⇒ STOP company thesis, keep OSS) · C3 signed tagged v0.2.0 + distribution + completions/man + quickstart + changelog (gate: 5 external testers <10 min to guarded session) · C4 `trace redact`, `policy explain`, newcomer docs, ICP memo as PRODUCT §0, open-core redraw in DIRECTION §9 · C5 quiet-at-diversity verdict (gates: <2 q/day median; <20% floor-off; <2× p95 build) · C6 day-90 decision memo, every criterion citing a committed measurement, recorded in DECISIONS.

### Months 3–6 — Phase D (conditional GO): control plane v0 (policy distribution, trace aggregation, SIEM story) (L); signed semver rule-pack channel with reserved `signatures:` fields (M); privileged boundary-tier spike — separate-UID supervisor / eBPF-LSM / fanotify broker — answering F1/F2/F3 at kernel grade (L); attach-mode matrix (measure or kill) (M); aarch64 + fail-closed ABI gating (M); live-correlation spike only on pilot demand (L); telemetry consent v2 design, still no backend code (M); Windows spike only on documented ICP pull, else committed Linux-only decision (M); second committer with merged PRs (S).

### Months 6–12 — Phase E (conditional GO + conversion): enterprise edition v1 (privileged tier, managed policy under `/etc/agent-firewall/`, un-disable-able *only at the privileged tier*, SIEM connectors, SLA'd feed); fleet telemetry under contract opt-in feeding the loop (G3: ≥30% consent); DFIR/evidence tier (hash-chained signed export, forensic report generator; 1 paid retainer); quarterly category watch (vendor sandboxes, eunomia, EDR modules, EU AI Act guidance / cyber-insurance questionnaires); growth instrumented against G1–G4.

**Traceability:** every stage-2 finding maps to a task (T-F1→B3/D3; T-F2→A9/D3; T-F3→A8/B2/D3; T-F4→B4; T-F5→B5; T-F6→A7; UX→B9; trust→A5/A6/C3; ticket anomaly→A10). Proposed Rohrpost filings (per project law, one ticket per milestone, gate in body — to be filed by the maintainer, not by this review): `[af-10]` M8 Trust & hygiene (Phase A); `[af-11]` M9 The named gaps (B2–B5); `[af-12]` M10 Headless wedge alpha (B1, C1, C3); `[af-13]` M11 Market evidence (B10, EXP-P1..P8); the re-created `[af-9]` precedes all.

---

## 15. Customer discovery, security validation, performance, usability, willingness-to-pay, and competitive experiments — with failure thresholds

All pre-registered; ≤$25k total; each experiment names its kill signal before it runs. (Future proposals, not current facts.)

| ID | Experiment | Design | Success signal | **Failure threshold (pre-registered)** |
|---|---|---|---|---|
| EXP-P1 | Problem interviews | 25 platform/sec eng at ≥20-dev orgs using coding agents; ≥10 with an agent incident; coded grid | Named owner + budget line for agent runtime risk | **<8/25 name an owner + budget ⇒ budgeted-problem thesis weakens; re-target or stop** |
| EXP-P2 | The 3am demo | Landing page + 90s video (migrate.sh→DROP DATABASE stop; overnight trace replay); 500 targeted visits | ≥3% booking rate | **<1% after 500 qualified visits ⇒ re-message before further spend** |
| EXP-P3 | Install friction | 10 external Linux devs, time-to-first-guarded-session | median <10 min | **>30 min median ⇒ distribution roadmap is the product; delay launch** |
| EXP-T4 | Perf bake-off | cargo build / npm ci / docker build × 5 real repos; monitor (filter-only and full) vs baseline vs Codex sandbox; p50/p95 | p95 <2× filter-only | **p95 >2× after Phase B tuning ⇒ daily-driver AND CI-wrapper stories die (CI has time budgets too)** |
| EXP-T5 | Quiet at diversity | 10 devs, ≥10 real projects, 2 weeks; questions/day, floor-off rate, build ratio, uninstall rate | median <2 q/day; <20% floor-off; <2× build | **median >3 q/day or >30% sessions with floor/filter off after tuning ⇒ "quiet" was a lab artifact; interactive product demoted** |
| EXP-T1 | io_uring deny compatibility | benign corpus + 5 real workloads under `io_uring_setup/enter` deny | zero breakage on compatible set | **material breakage ⇒ host-requirement posture; boundary tier becomes the only closure** |
| EXP-T2 | Hostile monitor harness | ptrace attach, `process_vm_writev`, `/proc/mem`, `pidfd_send_signal`, `pidfd_getfd`, external SIGKILL; Yama 0–3 | every route denied/sensed/named | **any unnamed open route ⇒ threat-model gap must be published before any security claim** |
| EXP-T3 | Descriptor inheritance matrix | hostile parent pre-opens files/dirs/sockets/pipes/memfds/pidfds; SCM_RIGHTS passing | closed-or-named for every capability | **SCM_RIGHTS open ⇒ named out-of-scope until boundary tier** |
| EXP-T6/T7/T8 | Landlock contract stress / TOCTOU race mutation / multi-distro replication | per §14 B4/B5/B6 | contract holds set-theoretically; no path-derived allow ever; numbers replicate | **any successful path-derived allow ⇒ API redesign before rule growth; ≥3/5 distro failures ⇒ reproducibility kill criterion fires; fix before any paid claim** |
| EXP-P5 | Headless pilots | 3 orgs wrap one CI job ×30 days | ≥1 real catch/near-miss; 0 merge-blocking false denies; <1 h/mo ops | **false denies block merges ⇒ rule pack not ready for unattended use; fix or stop** |
| EXP-P6 | Incumbent gravity | 5 CISO conversations ("CrowdStrike already covers this") | top-3 objections codified into roadmap | — (informative; expectations: central policy, Windows, SIEM) |
| EXP-P7 | WTP gate | paid pilots at $20/dev/mo list to every qualified org | ≥3 signed (≥$10k/yr equivalent) ⇒ GO | **0/30 qualified accept ⇒ STOP the company thesis; remain an OSS project** |
| EXP-P8 | DFIR probe | 3 evidence-tier conversations | 1 paid retainer | **0/3 engage ⇒ drop segment 2** |
| G3 | Telemetry consent (standing) | contract opt-in among paid seats | ≥30% consent ⇒ intelligence business possible | **<10% after enterprise pilots ⇒ kill the intelligence-company plan (tools business or sale)** |
| K2 | Credential leak (standing) | negative tests + outbox inspection | — | **one credential ever visible in a sample/outbox ⇒ end the telemetry program** |
| K3 | Overclaim (standing) | adversarial marketing/doc review per release | zero claims beyond the matrix | **one launch post contradicted by the bypass matrix ⇒ honesty asset spent; reputational stop** |

---

## 16. Recommended next 10 actions and the go/pivot/stop framework

### The next 10 actions, in order

1. **A1/A2 — make the gates deterministic** (fix the `af-monitor` flake and e2e T8/T11): nothing else is citable until the repo's own gates are green.
2. **A3 — stand up CI** with required checks, including `cargo test -p af-policy` for `policies/**` and `check.py`.
3. **A4 — number hygiene**: reconcile 147/152→155, fix `count-rules.py`'s three unclassified correlation rules, regenerate the benign summary with zero FAIL.
4. **A10 — resolve the Rohrpost incident**: re-create `[af-9]` from the transcript, reconcile the commit message, adopt pre-review hash snapshots of `.rohrpost`.
5. **A7 — ship the threat-model statement** (launch-mode, cooperative/accidental, tree-local, x86_64, not-hostile-peer) with the forbidden/required phrasing table, passed by an adversarial review.
6. **A8/EXP-T1 — decide io_uring** with a compatibility matrix; default-deny if the compatible set holds, else documented host posture.
7. **A9 — close inherited descriptors at launch** (`close_range`) and publish the SCM_RIGHTS scope note.
8. **A5/A6 — trust infrastructure**: SECURITY.md, signed commits, minisign release script, `cargo-deny` network ban for af-telemetry, 0600 artifacts, `DATABASE_URL` masking.
9. **B1 — ship `guard --ci`** (headless deny/report + JSON export) and run the 30-day self-pilot on one real CI job.
10. **B10/EXP-P1–P3 — run the market falsification program** (25 interviews, the 3am demo, install-friction test) and write the ICP memo into `docs/PRODUCT.md` §0.

### Go / pivot / stop framework

**GO (fund Phase D) requires ALL of:** Phase A gates green (CI, signing, reproducibility, threat-model statement); io_uring decision landed and defensible; **≥3 signed pilots ≥$10k/yr within 2 quarters of the wedge MVP** and pilot→paid conversion tracking ≥70% at ≥50% of list; quiet gates holding on real diversity (<2 q/day median, <20% floor-off, <2× p95 build); no replication failure on ≥3/5 distros.

**PIVOT ladders (pre-authorized, in order):** (1) *headless-only* — interactive product fails quiet/perf but CI pilots succeed ⇒ demote the interactive product to maintenance; sell the wedge. (2) *OSS tools vendor* — WTP fails (EXP-P7 = 0/30) but adoption grows ⇒ donations/services, no company. (3) *boundary-tier product* — enterprise demand insists on hostile-peer containment and funds it ⇒ Phase D/E becomes the product (requires the security hire; stated Linux-fleet ICP). (4) *evidence/DFIR product* — segment 2 out-converts platform teams ⇒ signed evidence, replay, retainer pricing.

**STOP the company thesis (keep the OSS project) if any of:** 0 paid pilots after 30 qualified demos; p95 >2× after two quarters of optimization; median >3 q/day after tuning on ≥10 real projects or >30% of sessions end with floor/filter off; ≥70% of competitive situations lost to EDR modules or vendor governance suites; quiet/perf claims fail replication on ≥3/5 distros unfixed; a credential ever leaks through a sample; one overclaiming launch post contradicted by the project's own bypass matrix.

**Watch triggers (quarterly):** telemetry consent <10% of paid seats post-pilots (kill the intelligence plan); any major runtime/CI platform ships default-on sandboxing **with** process-tree attribution and central policy (differentiation collapses — acquire, merge, or archive); regulation/insurance mandates *isolated* rather than *monitored* environments; a 6-month maintainer stall while eunomia or a vendor ships the interactive-approval variant.

**What would change the verdict toward funding as currently scoped:** procurement/RFP language at ≥3 recognizable orgs demanding vendor-neutral agent audit; Landlock ABI growth letting the 1.0× floor absorb most ptrace duties; a published, methodologically defensible statistic that ≥20% of corpus incidents occur in harness-external descendants vendor sandboxes cannot attribute; one agent platform adopting AF as its policy backend.

---

## Appendix — evidence index and confidence

**Repository facts (confidence: high — every item re-verified by this reviewer at cited lines):** rule counts 155/80/66/9 (derived from `policies/*.yaml`); `count-rules.py` exit 1; benign FAIL line on gitignored disk (`research/bypass/results/benign-summary.txt:4`); 361 tests; flaky monitor test (observed once by stage-2, green in targeted re-runs); e2e 53/54 this run / 52/54 stage-2 / 54/54 recorded at M6; `policy check` 155 valid; `policy test` 672 passed; `check.py` 90/255 agree; io_uring zero-events (`research/bypass/FINDINGS.md:86-88`); kill-filter scope and pidfd gap (`crates/af-monitor/src/seccomp.rs:43,311-313`); x86_64-only (`seccomp.rs:336,393`); yama-0 posture (`caps.rs:189`); Landlock writable TMP (`landlock.rs:358,594`); 120s timeout (`crates/af-approval/src/terminal.rs:17`); `DATABASE_URL` allowlist (`procfs.rs:25`); telemetry dependency proof (`cargo tree -p af-telemetry`); alpha banner (`crates/af-cli/src/run.rs:42`); ptrace ~10× (`crates/af-monitor/src/lib.rs:113-116`); product 11.0×/12.5× W2 (`research/spikes/inprocess/FINDINGS.md:145-146`); filter 1.16–1.92× (`research/spikes/seccomp-ptrace/FINDINGS.md:73-84,390`); TOCTOU 47.6% (`docs/DETECTION-RESEARCH.md:71,217`); doc staleness cluster (`docs/PRODUCT.md:81`; `docs/ARCHITECTURE.md:366`; `docs/DIRECTION.md:321`; `docs/MILESTONES.md:243`; `README.md:286`; `docs/DECISIONS.md:174`); no CI/SECURITY/tags/signing (57/57 `%G?`=N); placeholder URL (`Cargo.toml:23`); 9 tickets / 33 events at HEAD; `rp ready` empty; `.rohrpost` mtimes 22:55:34; no tracked reference to af-9/an4nm7; the an4nm7 ticket dump in the wave-1 transcript.

**Market claims (confidence as labeled in §9; primary URLs given inline; verified live by the stage-2 market cross-check 2026-08-31/09-01, sampled by this reviewer):** the space is fast-moving — re-verify star counts and ship status before any external use.

**Reviewer inference (labeled throughout):** the wedge thesis and ICP (§10.4), the psychosis diagnosis (§11.5), the remediation sequencing (§14), and all forward gates (§15–§16) are inferences and proposals, not current facts.

**Integrity disclosure (restated):** the wave-1 evidence artifact is tail-truncated (~32 KB/agent; 7 of 12 final reports absent, including three code-audit agents' and the Rohrpost auditor's); the workflow failed at its Challenge phase; an uncommitted open ticket and log event were destroyed during the review window by an unattributable cause; the HEAD commit message claims a filing its commit lacks. These facts limit what the review corpus can *prove* about first-pass conclusions (raw reads and repo re-verification carry the load) and must accompany any downstream use of this document. They do not overturn its verdicts.

*End of report.*
