# The Landlock contract

Date: 2026-09-01. This document is the set-theoretic contract of the kernel
floor that `crates/af-monitor/src/landlock.rs` enacts. It answers review
finding P1-7 (`docs/PROJECT-REVIEW.md` §13): the exact set of rights the
floor grants and denies, what Landlock cannot see, and where the credential
carve-out ends — including the holes, each with the mechanism that makes it
a hole and the measurement that proved it.

Everything here is **as built**. The code is the source of truth; where a
statement names a measurement, the measurement is regenerable:

- `research/spikes/landlock` (`make check`, section E, `bin/tmp-scope`) —
  the composition laws of the ruleset, measured on this kernel.
- `research/bypass/floor-stress.sh` — the stress matrix of §7, run against
  the real product.
- `tests/e2e.sh` sections K and U — the gated end-to-end anchors.
- `research/spikes/landlock/FINDINGS.md` — the original spike (escape
  attempts, blindness, cost).

Machine of this run: Fedora 43, kernel `7.0.9-105.fc43.x86_64`, Landlock
ABI 8 (`doctor` → `kernel_floor`).

---

## 1. What the floor is

One Landlock ruleset, built in the monitor before the child exists
(`Plan::build`, from the working directory and `$HOME`) and enacted in the
child before its first `execve` (`Plan::install`, after `PTRACE_TRACEME`,
before the seccomp filter). Landlock is an allow list with no deny rule:
every **handled** right is denied everywhere except under a path a rule
grants. The floor carries the "always no" rule classes of the built-in pack
(`Plan::enforced_rules`), so the session never needs to ask them; the
denial of an open on a hidden path is explained
(`Plan::denies`, the `kernel_denied` event).

The floor cannot be relaxed for a running session, is inherited by every
descendant, survives `execve`, and cannot be dropped by the program
(`research/spikes/landlock/FINDINGS.md`, escape attempts 0 of 6).

## 2. The negotiation: what the ruleset handles

`Plan::install` handles, per the ABI the kernel reports
(`availability`, at least ABI 1 required):

| Right group | Handled | Condition |
| --- | --- | --- |
| `READ_FILE`, `READ_DIR`, `EXECUTE`, `WRITE_FILE`, `REMOVE_DIR`, `REMOVE_FILE`, `MAKE_CHAR`, `MAKE_DIR`, `MAKE_REG`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK`, `MAKE_SYM` | yes | ABI 1 |
| `REFER` (link/rename across hierarchies) | yes | ABI ≥ 2 |
| `TRUNCATE` | yes | ABI ≥ 3 |
| `IOCTL_DEV` | **no, deliberately** | — |
| network (`handled_access_net`) | **no, ever** | always 0 |
| abstract-Unix-socket scope | no | — |
| `LANDLOCK_SCOPE_SIGNAL` | yes | ABI ≥ 6 |

Consequences worth naming: below ABI 2 a cross-hierarchy rename or link is
not restricted by the floor at all; below ABI 3 neither is a truncate; on
no ABI does the floor restrict a `connect` or a `bind` (the network rights
are never handled — network questions stay entirely with the pack);
`ioctl` on a held-open device is never mediated, because mediating it
would break terminals of normal work. The signal scope (ABI 6) is the one
non-filesystem restriction: no signal to a process outside the session.

## 3. The grant set

Built by `Plan::build`. Within a ruleset, a rule on a directory grants its
rights to **every path beneath it**; the effective rights on a path are the
union over all covering rules (§5). `rights_full` = the thirteen ABI 1
rights plus `REFER` (ABI ≥ 2) and `TRUNCATE` (ABI ≥ 3).

| Path class | Rule | Rights granted | Denied (within the handled set) |
| --- | --- | --- | --- |
| the work tree | one rule | `rights_full` | — |
| `/tmp`, `/var/tmp`, `/var/cache` | one rule each | `rights_full` | — |
| the entries of `$HOME` (enumerated once, at plan build) | one rule per entry | `rights_full`, files trimmed to object rights (below) | — |
| `$HOME/.ssh`, `$HOME/.aws/credentials`, `$HOME/.netrc`, `$HOME/.git-credentials` | **no rule** | none | everything handled: no open, no listing, no content¹ |
| `$HOME/.npmrc`, `$HOME/.pypirc`, `$HOME/.kube/config`, `$HOME/.docker/config.json`, `$HOME/.config/gh/hosts.yml` | one rule each | read + execute | every write-ish right |
| every directory on the path from `$HOME` down to a hidden path | **no rule** | none on the directory itself | the directory cannot be listed (the carve-out price) |
| `/usr`, `/etc`, `/opt`, `/srv`, `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64` | one rule each | read + list + execute | write, remove, make, refer, truncate |
| `/proc`, `/sys`, `/run`, `/var` | one rule each | read + list | execute, write, remove, make, refer, truncate |
| `/dev/null`, `/dev/full`, `/dev/tty`, `/dev/ptmx`, `/dev/pts`, `/dev/shm` | one rule each | read + write + execute + truncate (object rights) | the directory rights |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | one rule each | read + execute | write, truncate, the directory rights |
| everything else under `/dev` (raw disks included) | **no rule** | none | everything handled |
| `/mnt`, `/media`, `/run/media`, `/Volumes` | **no rule** | none | everything handled |
| every path under no grant (e.g. another user's home) | — | none | everything handled |

¹ `stat` on a hidden path still succeeds: Landlock mediates the open, not
the metadata (spike FINDINGS, "what it cannot see").

Object trimming: a rule that names something other than a directory — a
file, a device node — may carry only `READ_FILE | WRITE_FILE | EXECUTE |
TRUNCATE`; the kernel rejects the whole rule otherwise (`EINVAL`,
measured by the floor port). A work tree that sits beneath a hidden path
gets **no rule at all** (`work_tree_ungranted`): a grant on it would reach
the store underneath, so the floor prefers a session without a work-tree
grant over one that can read the store.

The hidden set is the pack's list and nothing more. `~/.gnupg`,
`~/.config/gcloud`, browser profile stores and service-account files are
**not** named by `filesystem.credentials.*` of the built-in pack, so the
floor hides none of them; they ride the ordinary home-entry grants, and a
write to them is judged by whatever pack rule matches (today: usually
none). Extending the hidden set is a pack change, not a floor change.

## 4. What the kernel answers (the enforced classes)

`Plan::enforced_rules`, with the ABI conditions of §2:

- `filesystem.etc.write` — no write under `/etc`.
- `filesystem.delete.system-path` — the writable exception paths of the
  rule (`/var/tmp`, `/var/cache`, `/dev/shm`) are exactly the floor's.
- `filesystem.delete.mount-root` — the media trees get no rule.
- `filesystem.credentials.write` — **only on the hidden prefixes**
  (`Plan::denied_prefixes`): see §6.
- `filesystem.device.truncate` (ABI ≥ 3), `process.signal.kill-everything`
  (ABI ≥ 6).

A held open whose path is under a denied prefix is released with an
explanation instead of a question (`run.rs`, `kernel_answers`); the
explanation is certain because the ruleset is immutable. Three `deny`
classes (`delete.root`, `device.destroy`, `signal.supervision`) are backed
by the floor without riding on it — the exec boundary stops them first.

## 5. The composition laws (measured)

How grants combine, each law measured (`research/spikes/landlock`
`make check`, section E; escape attempts in the same spike):

1. **Union within a layer.** Two rules that both cover a path grant the
   union of their rights; a rule deeper in the tree cannot subtract from a
   broader grant (`rule_specificity`: a narrow rule under a broad one
   left the subtree listable). A rule with `allowed_access = 0` is refused
   whole (`ENOMSG`).
2. **Layers intersect.** A second `restrict_self` can only restrict: the
   spike enacted a grant-everything ruleset on top of a restricted one and
   the denial held. Subtraction *via layering* is therefore expressible —
   but only by enumerating in the second layer everything that must stay
   allowed: whatever the second layer does not enumerate is denied,
   creation included (`tmp_scope`, scenario `layers`: `mkdir` at the root
   and a fresh file in an enumerated parent both `EACCES`).
3. **Rules attach to objects that exist when the ruleset is built.** A
   path created later inherits the grant of the deepest directory that
   covered it at creation time (`tmp_scope`, `covering`: a fresh
   `.ssh` chain created under a full grant is writable end to end).
4. **A carve-out is an enumeration, and enumeration is a snapshot.** Not
   granting a directory and granting every entry instead denies the shape
   — and denies every creation the enumeration does not reach
   (`tmp_scope`, `carve`: `mkdir` at the carved root `EACCES`). An
   enumeration that does not walk down to the shape misses it
   (`tmp_scope`, `bounded`).
5. **A make-only grant cannot create a file with content.** With every
   `MAKE_*` right and no `WRITE_FILE`, `open(O_CREAT|O_WRONLY)` fails
   `EACCES` — the create-with-write open needs `WRITE_FILE` from a
   covering rule (`tmp_scope`, `makeonly`). Scratch use dies with the
   shape.

## 6. The credential carve-out truth

**Where stores are hidden.** Exactly the four `Hide::Everything` paths and
the five write-hidden tool configs of §3, all under `$HOME`, fixed at plan
build. `$HOME` itself gets no rule, so nothing new can appear at its top
level during the session.

**The writable-tree hole.** A credential-shaped path — `.ssh`,
`.aws/credentials`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`,
`.kube/config`, `.docker/config.json`, `.config/gh/hosts.yml`, and any
other name the pack matches — under the work tree, `/tmp`, `/var/tmp`,
`/var/cache`, or inside any granted home entry, is **readable and writable
as far as the floor is concerned**. This is not a bug in the plan; it is
what the laws of §5 compose to: the grant on the tree covers the shape
(law 3), no rule can subtract it (law 1), a second layer would have to
enumerate a world-writable tree completely and would still deny every
later creation (laws 2 and 3), and scoping the grant to make-rights breaks
every scratch write (law 5). Closing it is therefore **impossible with the
shipped ABI**, and the mechanism is named: *path-beneath grants attach to
build-time objects and union; deny does not exist.*

What protects such a path instead:

| Filter mode | Read of a shape in a writable tree | Write to a shape in a writable tree |
| --- | --- | --- |
| `write-only` (default) | not held (reads are not stopped) | held, `filesystem.credentials.write` asks, denial explained |
| `all-opens` | held, `filesystem.credentials.read` matches and **reports** (its decision is `allow`), the read proceeds | same as `write-only` |
| `off` | allowed, silent — the floor is the only boundary and the hole is the boundary | allowed, silent |

Measured: `floor-stress.sh` S3 (read under `/tmp`, allowed), S4 (write
with filter off, allowed), S5/S6 (write with the default filter: one
question, `--approve deny` refuses, the key file never appears, stderr
names `filesystem.credentials.write`). The gated anchor is `tests/e2e.sh`
K9–K12.

**The bind-mount alias hole.** A bind mount is judged by its **mount
path**, not by the mounted object: `mount --bind $HOME/.ssh $WORK/mnt` and
the session reads the store through `$WORK/mnt` under the work-tree grant
(floor-stress S8, exit 0; the control S8c shows a non-hidden entry stays
usable through a mount, so it is the aliasing of the hidden object, not
mounts in general, that opens the store). The agent cannot reach this by
itself — a bind mount needs `CAP_SYS_ADMIN` — so this is an
environment-configuration hole: a privileged hand can place a readable
alias of a hidden store inside a granted tree. Naming it is the contract;
closing it is not expressible in the ABI (a rule would have to name the
mount path before the mount exists). The same measurement shows the
symmetric, benign case: a work tree that *is* a bind mount works normally
(S9).

**What aliases do not work.** A symlink is resolved to its object before
the kernel decides: a link in the work tree to the hidden key or to the
hidden `.ssh` directory is denied (`EACCES`, no question — S1, S2; the
control S2c shows a link to a granted entry works). A hard link out of a
hidden store is refused with `EXDEV`: no `REFER` right covers the pair
(S7; the spike measured the same).

**The explainer's limit on aliases.** `Plan::denies` maps the path as
written — the symlink path, not the resolved object — so the S1/S2 denials
produce no `kernel_denied` event and the user sees a bare `EACCES` (the
S1 trace holds `kernel_floor` but no `kernel_denied`). The path at a
seccomp stop is advisory by construction (a second thread can race it);
the decision is always the kernel's, on the object. The cost of that
soundness is that an alias-indirected denial explains itself as a plain
permission error.

**io_uring.** The per-syscall filter cannot see ring operations at all
(`research/bypass/FINDINGS.md`, gap 1). The floor can: an
`IORING_OP_OPENAT` with write intent on the hidden key, with the filter
off, fails `EACCES` and the key is unchanged (floor-stress S11; the gated
anchor is e2e U1–U7). One measurement, stated exactly: the floor mediated
this ring-issued open of a hidden store. It does not make the filter see
rings, and rules that must *ask* remain blind to them.

## 7. The stress matrix

`research/bypass/floor-stress.sh` regenerates this table; the raw runs of
this one are under `research/bypass/results/floor-stress/` (gitignored),
with the passing table preserved verbatim as `TABLE-2026-09-01.md`.
Machine: Fedora 43, kernel 7.0.9-105, Landlock ABI 8, run 2026-09-01.
13 of 13 rows HELD.

| case | what it tries | the contract says | verdict | measured |
| --- | --- | --- | --- | --- |
| S1 | symlink in the work tree to the hidden key | denied by the kernel: the rule names the object, not the path | HELD | exit=1 questions=0 |
| S2 | symlink in the work tree to the hidden `.ssh` | same | HELD | exit=1 questions=0 |
| S2c | control: symlink to a granted home entry | allowed | HELD | exit=0 questions=0 |
| S7 | hard link from the hidden key into the work tree | denied: no `REFER` between the hierarchies | HELD | exit=3, no copy |
| S3 | `.ssh` pre-placed under `/tmp`, read | allowed: the `/tmp` grant covers it; the pack reports | HELD | exit=0 questions=0 |
| S4 | `.ssh` created under `/tmp` during the session, filter off | allowed: the writable-tree hole | HELD | exit=0, content written |
| S5 | write to a `.ssh` under `/tmp`, default filter | denied by the pack question | HELD | exit=3, 1 question, file absent |
| S6 | write to a `.ssh` in the work tree, default filter | denied by the pack question | HELD | exit=3, 1 question |
| S8 | hidden `.ssh` bind-mounted into the work tree | named hole: the grant follows the mount path; a privileged hand made the alias | HELD | exit=0 questions=0 (a denial would flip this row and the contract) |
| S8c | control: granted entry bind-mounted into the work tree | allowed | HELD | exit=0 questions=0 |
| S9 | the work tree is a bind mount of a home entry | allowed: the session works in its work tree | HELD | exit=0 questions=0 |
| S10 | a git worktree at `/tmp` of a repo under the home | allowed: the repo's `.git` under the home is granted | HELD | exit=0 questions=0 commits=2 |
| S11 | `io_uring` write-intent open of the hidden key, filter off | denied: the floor mediates the ring-issued open of a hidden store | HELD | `blocked rc=-13`, key unchanged |

("HELD" means the outcome matched this contract; for S8 and S4 the
contract itself is the hole, so a HELD row there pins the hole as the
regression baseline — a future kernel or ABI that closes it flips the row
and this document must change.)

## 8. What the floor cannot see

From the spike (`FINDINGS.md`, "what it cannot see"), still true as built:

- the program name, the command arguments, the process chain — the exec
  boundary and the filter see those, the floor does not;
- SQL statement text, host names, network addresses: the floor handles no
  network right at all (§2);
- file mode bits: `chmod` is not mediated;
- ioctls: `IOCTL_DEV` is deliberately unhandled;
- file metadata: `stat` on a hidden path succeeds;
- an `execve` from an anonymous file descriptor (a `memfd`): it runs
  (measured in the spike); the exec boundary, not the floor, is what
  stops a judged program from starting.

A rule whose answer depends on any of these keeps its question.

## 9. Budget evidence

The floor change of this ticket is documentation and tests: the grant set
is byte-identical to the ML floor, so the interruption budget cannot move.
Measured anyway, as every floor claim must be:

- Benign corpus (`research/bypass/benign.sh`), floor on, three filter
  modes. The rows of this run (2026-09-01, ledger
  `research/bypass/results/benign-summary.txt`): `off` quiet; `write-only`
  and `all-opens` ended `fw_exit=3` with **6 questions each — all six the
  `deny` of `tamper.bypass.io-uring` on `io_uring_setup`**, a rule of the
  in-flight `[af-12]` io_uring pack change (`policies/tamper.yaml`,
  uncommitted), not a floor rule: the corpus processes fell back (the
  session itself exited 0) and the floor grants nothing to any question.
  The ledger's rows under the committed pack (same script, same machine)
  are 0 questions / 0 agent tags / 0 quarantines in all three modes. The
  budget call on that rule belongs to its own deliverable.
- Bench (`research/bench/floor.sh`, medians of 7): **blocked at the time
  of writing** — the yama incident of 2026-09-01
  (`docs/DECISIONS.md`, 2026-09-01) left `ptrace_scope` locked at 3, and a
  product session at scope 3 cannot start; `floor.sh` then measures a
  ~140 ms fast-fail and still exits 0, so its numbers are garbage by
  construction (the run was discarded, see the decision log). The last
  valid measurement of the floor is the ML one — 0.98×–1.03× on/off
  across W1/W2/W3 (`research/spikes/landlock/FINDINGS.md`, "The corpus and
  the bench") — and this ticket changes none of the code that measurement
  exercised. The two fresh runs the ticket asks for are first in the
  post-reboot queue behind `scripts/gate.sh`.

## 10. Change record

| date | change | evidence |
| --- | --- | --- |
| 2026-08-31 | the floor ships (ML): grant set of §3, explainer, pack re-count | `landlock.rs`, spike FINDINGS, e2e K1–K8 |
| 2026-09-01 | this contract (af-12, P1-7): composition laws measured (`tmp_scope`), stress matrix (S1–S11), the writable-tree and bind-mount holes named, `/tmp`-shape denial pinned in e2e (K9–K12) | `research/spikes/landlock` section E, `research/bypass/floor-stress.sh`, this document |
| 2026-09-01 | evidence state: floor-stress 13/13 and e2e 65/65 (incl. K9–K12) ran at `ptrace_scope` 0 before the yama lock; `af-monitor` landlock tests 9/9, spike `make check` 85/85 and count-rules exit 0 ran after it (they need no ptrace); the fresh bench pair is queued behind the reboot (`docs/DECISIONS.md`, 2026-09-01) | `results/floor-stress/` (e2e log: `e2e-2026-09-01.log`), this section |
