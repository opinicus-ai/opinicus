---
name: False negative report
about: A dangerous action passed with no question and no denial. These reports decide which rules and which gap measurements come next.
title: "[false-negative] "
labels: false-negative
---

A false negative is **a dangerous action that produced no question, no
refusal and no report**. Two outcomes are possible: a rule is missing, or
the action rode one of the named bypasses — and both are useful.

**Read [docs/THREAT-MODEL.md](../../docs/THREAT-MODEL.md) §5 first.** If
the action went through one of these, it is a known, measured gap and the
report goes to that gap's measurement work rather than a new rule:

* `io_uring` (zero events in every filter mode);
* a capability that was already open — a live or inherited descriptor;
* an attack on the monitor itself (same-user, unheld surfaces);
* content sent over an already-open connection;
* a delete/rename inside a granted tree, or an unlink of a trace file.

**Before you post:** redact secrets. Command lines, paths and selected
environment values are private data; strip credentials, tokens and
internal host names.

## What the dangerous action was

<!-- What ran, and why it was dangerous (data loss, infrastructure
destruction, credential exposure…). -->

## What should have happened, in your view

<!-- A question, a refusal, or at least a report — and if you can name the
shape of the rule that should fire, name it. -->

## Did it match a named bypass?

<!-- Yes, which one (see docs/THREAT-MODEL.md §5) / No / Not sure. -->

## How to reproduce it

<!-- The command line, ideally minimal. If reproduction needs a live
credential or a real server, describe the shape instead — do not paste
secrets. -->

## Trace excerpt (optional, redacted)

<!-- From the `--trace` file of the session, secrets removed. An action
that no rule matched is dropped by the default retention; re-run with
`--retention all` if you need it recorded. -->

## Environment

* commit built: `git rev-parse HEAD` =
* distribution and kernel:
* architecture:
* `--syscall-filter` mode (default `write-only` / `all-opens` / `off`):
* Landlock floor on (default) or `--landlock off`:
