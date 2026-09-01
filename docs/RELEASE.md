# Release signing and verification policy

Status: **definition plus one executable dry-run.** This document is the
policy skeleton that milestone M14 (`[af-15]`) must fill in and execute for
real; the two-job pipeline in `.github/workflows/ci.yml`
(`sign-and-upload` → `verify-on-second-machine`) is its dry-run, running on
every push with an **ephemeral** key generated inside the CI job. What does
not exist today, stated plainly: a release channel, a production signing
key, enforcement of signed commits, `cargo auditable` builds, or an SBOM.
Nothing in this document distributes anything — external distribution is
gated on M10's exit and M14 ([MILESTONES.md](MILESTONES.md)).

What is enforced today (as built, 2026-09-01):

* The gate's supply-chain step: `cargo deny check advisories bans licenses
  sources` and `cargo audit --deny warnings` ([`scripts/gate.sh`](../scripts/gate.sh),
  [`deny.toml`](../deny.toml)). Measured on that date: all four deny checks
  `ok`, `cargo audit` 0 vulnerabilities / 0 warnings against the live
  RustSec database.
* The af-telemetry no-network dependency contract, enforced by `cargo
  test` ([`crates/af-telemetry/tests/dependency_contract.rs`](../crates/af-telemetry/tests/dependency_contract.rs))
  and by the workspace-wide network-crate ban in `deny.toml`.

## 1. Signed commits (definition)

Maintainers sign every commit and tag that reaches `main`, with a key whose
fingerprint is recorded here when the policy is activated. This is a policy
of the maintainers, not yet an enforced branch protection: enabling GitHub's
required-signature rules is an org setting deliberately left **off** until
the M14 release work turns this section on. Until then, commits are signed
voluntarily and nothing claims otherwise.

## 2. Artifact signing with minisign

Every released artifact ships as a bundle with:

* the artifact files themselves;
* `SHA256SUMS` — one `sha256sum`-format line per file, relative paths;
* `SHA256SUMS.minisig` — a detached minisign signature over `SHA256SUMS`,
  with a trusted comment recording the release and commit it was made for.

Two layers, two failures: the signature proves the manifest is the one that
was signed; the manifest proves each file is the one that was hashed. A
tampered file fails `sha256sum -c`; a tampered manifest fails `minisign
-V`; both are exercised as negatives in the dry-run (§4).

Key policy:

* **Production key** (M14, not yet created): a dedicated signing key,
  password-protected, held by the releasing maintainer, never stored in CI
  or in this repository. The matching public key is published out-of-band —
  in this file, in the release notes, and on the project page — before the
  first signed release. Rotation invalidates trust in old releases only if
  announced here; the old key's last valid release is recorded.
* **Dry-run key** (today): generated per CI job with `minisign -G -W`, kept
  only in the runner's temporary storage, destroyed with the runner. It
  proves the pipeline mechanics; it anchors no trust.

## 3. Key publication and channels

The channel that carries the bytes must not be the only channel that
carries the key. In the dry-run the bundle travels through the GitHub
artifact store while the public key travels through the workflow's job
outputs — a separate path a tampered artifact cannot rewrite. In a real
release the bytes travel via the release page and the public key via this
document and the project page. An evaluator who receives both from the same
GitHub page should additionally check the key fingerprint against a second
source (the README mirror or a maintainer) before trusting a first install;
that guidance moves to the quickstart when M14 writes it.

## 4. The CI dry-run and how its checks have teeth

`.github/workflows/ci.yml`:

1. `sign-and-upload` — builds the release, stages the dry-run bundle (the
   binary plus the `policies/` packs), writes `SHA256SUMS`, generates the
   ephemeral key, signs the manifest, deletes the secret key, uploads the
   bundle, and passes the public key on as a job output.
2. `verify-on-second-machine` — a second runner that receives only the
   downloaded bundle plus the public key, and must:
   * pass `minisign -V -p minisign.pub -m SHA256SUMS` (signature);
   * pass `sha256sum -c SHA256SUMS` (every file hash);
   * **fail** `minisign -V` on a copy of `SHA256SUMS` with one flipped
     byte (signature copied alongside): if the corrupted manifest verifies,
     the job fails — a check that cannot fail is not a check;
   * **fail** `sha256sum -c` on a bundle whose `agent-firewall` binary has
     one flipped byte: the manifest row must be reported `FAILED`.

minisign is installed pinned and checksum-verified (version `0.12`, one
sha256 recorded in the workflow) because it is absent from
`taiki-e/install-action`'s tool manifest and the crates.io `minisign`
crate is library-only (checked 2026-09-01); the pinned values change only
in a reviewed commit.

## 5. Verification steps for an evaluator

Once a real signed release exists (M14):

```sh
sha256sum -c SHA256SUMS
minisign -V -p minisign.pub -m SHA256SUMS   # minisign.pub from RELEASE.md, not the bundle
```

Until then, the commands above are exercised only by the CI dry-run and by
whoever replays it locally; the ephemeral dry-run key validates nothing
outside its own workflow run.

## 6. cargo auditable and SBOM (plan)

Today's floor: the dependency set is fixed by the committed `Cargo.lock`
and checked by `cargo deny` (advisories, licenses, sources, the no-network
bans) and `cargo audit` on every push. The M14 release work adds:

* `cargo auditable` builds, embedding the locked dependency list into the
  binary so `cargo audit bin` works on the shipped artifact itself;
* an SBOM (format decided at M14; `cargo cyclonedx` is the current
  candidate) attached to the release and covered by the same
  `SHA256SUMS`/minisign layer.

Both are plan, not as-built; this file says so until they exist.

## 7. Distribution rule

No external distribution of any artifact occurs before the M10 exit gate
passes (two independent adversarial reviews, all checks green) and M14
produces a signed versioned artifact ([MILESTONES.md](MILESTONES.md)). The
CI dry-run bundle is retained for days, is signed by a key that dies with
the job, and must never be published as a release.
