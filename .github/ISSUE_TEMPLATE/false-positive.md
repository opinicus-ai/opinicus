---
name: False positive report
about: The firewall asked a question, refused or stopped an action that a normal development session needs. Quiet is the feature (docs/PRODUCT.md §5), so every case of noise is a real bug.
title: "[false-positive] "
labels: false-positive
---

A false positive is **a normal action that was questioned, refused or
stopped**, where the session was doing ordinary work. Reports feed the
interruption budget directly: a rule that cannot prove a quiet negative
does not ship ([docs/POLICY.md](../../docs/POLICY.md) §6).

**Before you post:** redact secrets. Traces, command lines and selected
environment values are private data; a URL-valued name such as
`DATABASE_URL` keeps its user name and host in a trace (the password is
masked to `<redacted>` at capture). Strip anything you would not paste
into a public log.

## The question or refusal, verbatim

<!-- Paste the exact prompt text: the chain, the attempted operation, the
rule and the reason. `policy list` names the rule if you no longer have
the session text. -->

## What the session was doing

<!-- The command you ran and what normal work it belongs to (a build, a
test run, a package manager, git maintenance, a container workflow…). -->

## The rule that fired

<!-- The rule id from the prompt or from `agent-firewall policy list`.
If you do not know it, leave this empty. -->

## How often it fires

<!-- Once per session, per command, per commit… Frequency is what the
budget measures. -->

## Trace excerpt (optional, redacted)

<!-- A few lines around the decision from the `--trace` file, secrets
removed. -->

## Environment

* commit built: `git rev-parse HEAD` =
* distribution and kernel:
* architecture:
* `--syscall-filter` mode (default `write-only` / `all-opens` / `off`):
* Landlock floor on (default) or `--landlock off`:
