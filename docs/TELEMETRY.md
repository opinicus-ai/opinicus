# Telemetry

The packaging spec of the optional early-access telemetry, and the consent
flow that governs it. This document is **as built**: everything here is
shipped code, and every number names its source. The direction it serves is
[DIRECTION.md](DIRECTION.md) §7; the decision that binds it is
[DECISIONS.md](DECISIONS.md), 2026-08-30: *telemetry is opt-in, never a
condition*.

The one-line summary:

> Telemetry is off by default. A user grants single scopes, can revoke
> them at any time, and every sample is a local file that the user inspects
> and destroys. **Nothing is sent anywhere.** No code exists that could.

## 1. What a sample is

A **sample** is one small, redacted, pseudonymized JSON extract of a
recorded session, centered on a **trigger**:

| trigger | why it is a trigger |
| --- | --- |
| `quarantine_started` | a rule suspended the whole tree for a ruling |
| `tamper`, `signal_send` | an attack on the firewall's own visibility |
| `discrepancy` | the expected view and the observed view disagreed |
| `approval_requested` | the firewall asked the user |
| `policy_decision` with a decision above `allow` | a rule refused or stopped an action |

Around each trigger the sample carries a **window of 20 events before and
20 after** (`af-telemetry` `DEFAULT_WINDOW`). Triggers whose windows overlap
or touch merge into one sample, so a burst of questions produces one
extract, not twenty near-copies (measured in
`crates/af-telemetry/tests/sample.rs`:
`far_apart_triggers_make_two_samples_with_a_small_window`). A session
without a trigger makes no sample.

The sample file is pretty-printed JSON, one file per sample, named
`sample-<session>-<number>.json` in a local **outbox** directory. A text
editor is a complete inspector; `agent-firewall telemetry inspect` adds a
summary line. Both the sample files and the consent file below are created
with the permission mode `0600` (`af-telemetry` `write_private`), because
they name the machine and its sessions even after redaction.

## 2. The consent flow

Consent lives in one local file,
`$XDG_CONFIG_HOME/agent-firewall/telemetry.json`
(`$HOME/.config/…` on a machine without `XDG_CONFIG_HOME`), and nowhere
else:

* **Off by default.** No file exists until the user grants something, and a
  missing file *is* off, not an error.
* **Granular.** Five scopes, each granted on its own:

| scope | what it lets a sample carry |
| --- | --- |
| `tree` | the process tree: parent links, program names, executable paths, executable hashes |
| `actions` | command lines, file paths, connection targets, the evidence lines of sensed facts |
| `content` | the content of standard input and of read files — the most sensitive scope, redacted and capped even when granted |
| `env` | environment variable **names**; the values never travel, whatever this scope says |
| `identity` | which agent the detectors named, with what confidence and what signals |

* **Revocable.** `telemetry off` revokes one scope or all of them, at any
  time. A consent file of a newer version that names an unknown scope
  degrades quietly: the known scopes load, the unknown one is skipped.
* **Never a condition.** No other command reads the consent file. `run`
  reads it only when the session itself passes `--telemetry`, and a refusal
  there writes nothing and fails nothing. With telemetry off the product is
  complete.

The command surface:

```console
$ agent-firewall telemetry status                 # the consent state, the outbox, the disclosure
$ agent-firewall telemetry on --scope tree --scope actions
$ agent-firewall telemetry off --scope content    # or no --scope: everything
$ agent-firewall telemetry sample session.jsonl   # packages a recorded trace
$ agent-firewall telemetry inspect out/sample-s-…-001.json
$ agent-firewall telemetry destroy --all
```

And the session-integrated path, which needs no trace file because the
session keeps its own events in memory:

```console
$ agent-firewall run --telemetry -- claude
```

`--telemetry` opts the session in; the consent file still decides whether
anything is written. `--telemetry-config PATH` and `--telemetry-outbox
PATH` relocate the two files for a test or a shared machine.

## 3. Redaction by design

Redaction is not a pass over the finished sample; it is how every field is
chosen. The pattern is the monitor's environment-value redaction
([RESEARCH.md](RESEARCH.md) §4), generalized to every free text a sample
can carry.

### What is dropped by default

| content | treatment |
| --- | --- |
| environment **values** | never travel, in any scope; `env_change` events carry the name only, `ProcessInfo.env` carries every value as `<redacted>` |
| observed content (`stdin_write`, `file_read` data, input actions) | dropped unless `content` is granted; then secret-redacted and cut to 2000 characters (`MAX_CONTENT_CHARS`) with a visible `…<cut>` marker |
| the session baseline | never travels — the git remotes of a work tree name a private repository, and no rule needs them here |
| absolute time | never travels; every event carries `at_ms`, milliseconds after the session start |
| ungranted scopes | the field is absent, not empty: a sample without `actions` holds no `argv`, no paths, no evidence lines |

### What is pseudonymized

| identifier | treatment |
| --- | --- |
| session id | `s-` + the first 12 hex of its SHA-256 — two samples of one session join, the machine's identifier does not travel |
| process ids | `p1`, `p2`, … in order of first appearance in the whole trace, so the same process keeps the same reference in every sample |
| the home directory | replaced with `<home>` wherever it appears |
| any login under `/home/<login>` or `/Users/<login>` | replaced with `<user>`, so another user's tree keeps its depth and file names without naming anybody |
| the host name | replaced with `<host>` wherever it appears |

Paths otherwise stay whole — directories, file names, extensions — because
the rules of the research pipeline match on them
(`redaction::Pseudonyms::path`).

### What is secret-redacted

Any free text — a command line, observed content, an evidence line, a rule
reason — passes `redaction::redact_text`:

* an **assignment whose name holds a secret marker** keeps its name and
  loses its value: `password=hunter2` becomes `password=<redacted>`. The
  markers are the monitor's, unchanged: `PASSWORD`, `PASSWD`, `TOKEN`,
  `SECRET`, `KEY`, `CREDENTIAL`, `AUTH`, matched case-insensitively and by
  fragment. `Authorization: Bearer <token>` loses the token and keeps the
  scheme.
* a **credential that carries a known prefix** is swallowed whole:
  `sk-…`, `sk-ant-…`, `sk-proj-…`, `ghp_…`, `gho_…`, `github_pat_…`,
  `xox…`, `AKIA…`, each requiring at least eight following word
  characters.
* The matcher **errs toward redaction**: a word that merely contains a
  marker (`keyboard`) redacts too. A sample that redacts too much is a
  smaller sample; a sample that leaks a credential is a product failure.

The executable hashes of the tree (`sha256:<hex>` of the program file,
files up to 256 MiB, `MAX_HASH_BYTES`) name a program without naming the
user's copy of it.

### What a sample may contain

With every scope granted, one sample carries: the schema marker
(`af-telemetry-sample/1`), the pseudonymized session reference, the scopes
that were granted at packaging time, the agent identity (name, confidence,
signals), the reasons (trigger kind, rule, `at_ms`), the process tree
(reference, parent, comm, pseudonymized exe, hash), and the redacted event
window — process events, file and network actions, policy decisions with
their rule matches and reason prose, questions and answers, tamper and
discrepancy facts, kernel floor and denials, monitor warnings. The unit
test `no_secret_baseline_session_id_or_raw_pid_reaches_the_sample_text`
proves the negative half on a session that carries a secret on the command
line, in the environment, on standard input and in the baseline.

## 4. Inspectable before it leaves — and it never leaves

The alpha ships the packaging and the consent flow only. The research
backend of DIRECTION.md §8 **does not exist**: not a server, not a client,
not a stub, not an upload queue. The dependency tree says so
(`cargo tree -p af-telemetry`): `af-core`, `serde`, `serde_json` — no
socket library among them, and no code in the workspace opens a network
connection for telemetry. The tree is enforced, not just described:
`crates/af-telemetry/tests/dependency_contract.rs` pins the direct set and
the shipped closure and fails `cargo test -p af-telemetry` on any change,
and the root `deny.toml` bans the network-capable crates workspace-wide
([RELEASE.md](RELEASE.md)).

A sample's complete life is local:

```text
generated  -> agent-firewall telemetry sample <trace>   (or run --telemetry)
inspected  -> a text editor, or telemetry inspect <file>
destroyed  -> rm, or telemetry destroy [FILE…] --all
```

`telemetry status` counts what waits in the outbox, and the outbox is
`${XDG_DATA_HOME:-$HOME/.local/share}/agent-firewall/outbox` by default.
Destruction is `remove_file`; no archive, no trash, no copy.

## 5. The disclosure

The alpha disclosure — printed by every `run`, by `doctor`, and stated in
the README:

> **Alpha release — not a production security boundary.** False positives
> and false negatives are expected; never rely on it as your only
> protection.

Two properties of the disclosure are deliberate:

* It is printed by the binary itself, on standard error, before every
  session — a user who never opens the README still sees the limits.
* The telemetry commands each repeat that nothing is sent anywhere. The
  audience most likely to install a security monitor is the audience most
  likely to refuse telemetry ([PRODUCT.md](PRODUCT.md) §3), and the only
  honest answer is the local outbox.

## 6. What is not here, on purpose

* **The research backend and the analysis-agent automation** (DIRECTION.md
  §8). The manual workflow of `research/threats/` continues as the
  pipeline's front end; a future backend will have to accept samples that
  this spec already makes safe to hand over.
* **Automatic sampling without `--telemetry`.** A session that does not
  opt in never reads the consent file.
* **Any promise about the future of consent.** A backend that wants
  samples will take them from the outbox under whatever terms the user
  agreed to then; nothing in this crate prepares, stages or pre-consents.

## 7. Where the code is

| piece | where |
| --- | --- |
| scopes, consent, the consent file | `crates/af-telemetry/src/lib.rs` |
| redaction and pseudonymization | `crates/af-telemetry/src/redaction.rs` |
| triggers, windows, sample building, the outbox | `crates/af-telemetry/src/sample.rs` |
| the SHA-256 of executable hashes | `crates/af-telemetry/src/sha256.rs` |
| the CLI commands | `crates/af-cli/src/telemetry_cmds.rs` |
| the session-integrated path | `crates/af-cli/src/run.rs` (`--telemetry`) |
| the packaging measurements | `crates/af-telemetry/tests/sample.rs`, `crates/af-cli/tests/cli.rs` |
