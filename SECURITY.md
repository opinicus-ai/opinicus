# Security policy

## Supported state

This project is an **alpha**. The version is 0.1.0, the platform is Linux
(the syscall filter is `x86_64`-only), and the only way to obtain the
software today is to build it from source. There are **no releases and no
tags**, and **commits are not signed yet** — verified on the current
`main` history (`git log --format=%G?` returns `N`). Signed commits,
signed artifacts, SBOM and release verification are defined by milestone
M10 and ship with the first signed distribution (M14,
[docs/MILESTONES.md](docs/MILESTONES.md)); do not trust any binary that
claims to be a release before then.

Before reporting anything, read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
It states what the alpha guarantees, what is advisory, and which bypasses
are already measured and named. The binary states the same on every run:
*alpha release — not a production security boundary*
(`crates/af-cli/src/run.rs:42`).

## What counts as a security issue here

**Report privately** (next section) if you find:

* a way to cross a boundary the threat model lists as a **guarantee**
  ([docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §3) that is not one of the
  named bypasses — a traced descendant that starts a new program without
  the exec stop, a held call that proceeds unheld, a floor deny that can
  be relaxed from inside the session;
* **a soundness violation**: an `allow` decision that rests on a path or
  address read from the memory of the judged program
  ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3a, the soundness rule);
* **a privacy defect**: a secret that survives the redaction paths into a
  telemetry sample, or a file written with broader permissions than its
  content allows;
* **a supply-chain issue**: a compromised or advisory-affected dependency.

**Not new vulnerabilities** — measured, named and tracked, with their
evidence in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §5: the
`io_uring` complete bypass, live/inherited descriptors, the same-user
monitor attack surface, the `x86_64`-only filter, invisible content on
open connections, and the unlink-of-evidence gaps. Reconfirmations of
these on new kernels or distributions are still welcome — file them as
false-negative reports (below) so they feed the M11 measurement work
rather than the advisory flow.

## Reporting a vulnerability

Use GitHub security advisories, privately:

**https://github.com/opinicus-ai/opinicus/security/advisories/new**

Please do not open a public issue for a vulnerability. Include, where you
can:

* the exact commit you built (`git rev-parse HEAD`);
* distribution, kernel version, architecture, `yama/ptrace_scope` and
  `kernel/io_uring_disabled`;
* a minimal reproduction — a command line is ideal;
* an excerpt of the session trace (`--trace`), **redacted**: traces hold
  command lines, paths and selected environment values. A URL-valued
  environment name such as `DATABASE_URL` keeps its user name and host —
  the password of the userinfo is masked to `<redacted>` at capture
  (`af-monitor` `mask_userinfo`) — so a trace still names machines and
  accounts: treat it like a log file with private data and strip secrets
  before pasting.

## What to expect

This is a single-maintainer alpha with no response-time contract. The
honest commitments are:

* **Acknowledgment**: as fast as one maintainer can manage; a target of
  days, not hours, and no promise beyond that.
* **Assessment against the threat model**: every report is checked against
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — if it crosses a listed
  guarantee, it is a vulnerability; if it confirms a listed bypass, it is
  recorded as evidence for the milestone that measures it.
* **Coordinated disclosure**: fixes land with a test that fails before the
  fix; the advisory is published after the fix is in the repository, or
  after an agreed window if a fix takes longer. Credit is given if you
  want it.
* **No bounty** is offered.

## False positives and false negatives

The interruption budget is the product
([docs/PRODUCT.md](docs/PRODUCT.md) §5): a guardrail that asks too many
questions gets switched off, so every report of noise is a real bug.

* **False positive** — a normal action was questioned, refused or stopped,
  and a normal development session needs it: use the
  *False positive report* issue template
  (`.github/ISSUE_TEMPLATE/false-positive.md`).
* **False negative** — a dangerous action passed with no question and no
  denial: use the *False negative report* issue template
  (`.github/ISSUE_TEMPLATE/false-negative.md`). Check
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §5 first: if the action
  rode a named bypass, the template will route it to the gap's ticket
  rather than a rule change.

Maintainers: that routing needs the `false-positive` and `false-negative`
labels to exist on the repository — GitHub silently drops a template label
that does not exist, and the default label set has neither.
`scripts/issue-labels.sh` creates both (one `gh label create` per label,
safe to re-run); run it once on any repository that adopts the templates.

These reports are user-initiated GitHub issues. The product itself has no
telemetry and no upload code — nothing about your sessions is sent
anywhere unless you choose to paste it into a report
([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3f).
