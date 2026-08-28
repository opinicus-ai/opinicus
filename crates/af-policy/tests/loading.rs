//! Tests of the loader, of the lint and of every match predicate.

mod common;

use std::path::PathBuf;

use af_core::{Decision, PolicyEngine, RiskLevel};
use af_policy::{PolicySet, Severity};
use common::{connect, exec, exec_in, file_open, ids};

/// Returns the directory with the rule files of the test.
fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/pack")
}

/// Builds a set from one rule and stops the test when it does not load.
fn set_from(text: &str) -> PolicySet {
    PolicySet::from_str(text, "test.yaml").expect("the test rules load")
}

// ---------------------------------------------------------------------------
// Loading errors
// ---------------------------------------------------------------------------

#[test]
fn a_bad_regex_is_a_load_error_that_names_the_rule_and_the_file() {
    let text = r#"
version: 1
name: test.bad-regex
description: A rule with a pattern that does not compile.
rules:
  - id: test.bad
    title: Bad pattern
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      argv_matches: '([unclosed'
"#;
    let error = PolicySet::from_str(text, "rules/bad.yaml").expect_err("the load fails");
    let message = error.to_string();
    assert!(message.contains("rules/bad.yaml"), "{message}");
    assert!(message.contains("test.bad"), "{message}");
    assert!(message.contains("argv_matches"), "{message}");
}

#[test]
fn an_unknown_field_is_a_load_error() {
    let text = r#"
version: 1
name: test.typo
description: A rule with a field name that has a typo.
rules:
  - id: test.typo
    title: Typo
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      argv_match: 'rm'
"#;
    let error = PolicySet::from_str(text, "rules/typo.yaml").expect_err("the load fails");
    let message = error.to_string();
    assert!(message.contains("rules/typo.yaml"), "{message}");
    assert!(message.contains("argv_match"), "{message}");
}

#[test]
fn an_unknown_field_of_a_rule_is_a_load_error() {
    let text = r#"
version: 1
name: test.typo
description: A rule with an unknown key.
rules:
  - id: test.typo
    title: Typo
    category: test
    risk: low
    decision: allow
    reason: test
    severity: high
    match:
      action: exec
      program: [rm]
"#;
    let error = PolicySet::from_str(text, "rules/typo.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("severity"), "{error}");
}

#[test]
fn a_repeated_rule_id_in_one_file_is_a_load_error() {
    let text = r#"
version: 1
name: test.double
description: Two rules with the same identifier.
rules:
  - id: test.same
    title: One
    category: test
    risk: low
    decision: allow
    reason: test
    match: { action: exec, program: [rm] }
  - id: test.same
    title: Two
    category: test
    risk: low
    decision: allow
    reason: test
    match: { action: exec, program: [dd] }
"#;
    let error = PolicySet::from_str(text, "rules/double.yaml").expect_err("the load fails");
    let message = error.to_string();
    assert!(message.contains("test.same"), "{message}");
    assert!(message.contains("two times"), "{message}");
}

#[test]
fn a_repeated_rule_id_of_the_builtin_pack_is_a_load_error() {
    let path = data_dir().join("extra.yaml");
    let error = PolicySet::load(&[path.clone(), path], false).expect_err("the load fails");
    let message = error.to_string();
    assert!(message.contains("local.extra.marker"), "{message}");
}

#[test]
fn an_unknown_format_version_is_a_load_error() {
    let text = "version: 2\nname: test.future\ndescription: A newer format.\nrules: []\n";
    let error = PolicySet::from_str(text, "rules/future.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("version 2"), "{error}");
}

#[test]
fn a_pack_without_a_name_is_a_load_error() {
    let text = "version: 1\nname: ''\ndescription: No name.\nrules: []\n";
    let error = PolicySet::from_str(text, "rules/anon.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("no name"), "{error}");
}

#[test]
fn a_missing_file_is_a_load_error_that_names_the_path() {
    let path = data_dir().join("does-not-exist.yaml");
    let error = PolicySet::load(&[path], false).expect_err("the load fails");
    assert!(error.to_string().contains("does-not-exist.yaml"), "{error}");
}

// ---------------------------------------------------------------------------
// Loading from disk
// ---------------------------------------------------------------------------

#[test]
fn a_directory_gives_every_rule_file_and_skips_other_files() {
    let set = PolicySet::load(&[data_dir()], false).expect("the directory loads");
    let rule_ids: Vec<String> = set.rules().into_iter().map(|r| r.rule_id).collect();
    assert!(rule_ids.contains(&"local.extra.marker".to_string()));
    assert!(rule_ids.contains(&"filesystem.shred".to_string()));
    assert_eq!(rule_ids.len(), 2, "the text file must stay out: {rule_ids:?}");
}

#[test]
fn a_local_rule_replaces_a_builtin_rule_with_the_same_id() {
    let builtin = PolicySet::builtin().expect("the built-in pack loads");
    let with_local = PolicySet::load(&[data_dir()], true).expect("the pack loads");
    assert_eq!(with_local.len(), builtin.len() + 1 - 1);

    let case = exec(&["shred", "-u", "secrets.txt"]);
    assert!(!builtin.evaluate(&case.ctx()).matches.is_empty());
    assert!(
        with_local.evaluate(&case.ctx()).matches.is_empty(),
        "the local rule switches the built-in rule off"
    );

    let local = exec(&["deployctl", "release"]);
    assert!(!with_local.evaluate(&local.ctx()).matches.is_empty());
}

#[test]
fn merge_adds_the_rules_of_another_set() {
    let mut set = set_from(
        "version: 1\nname: test.a\ndescription: First.\nrules: []\n",
    );
    assert!(set.is_empty());
    let other = PolicySet::builtin().expect("the built-in pack loads");
    let count = other.len();
    set.merge(other);
    assert_eq!(set.len(), count);
    assert!(!set.is_empty());
}

#[test]
fn a_rule_that_is_switched_off_never_matches() {
    let set = set_from(
        r#"
version: 1
name: test.off
description: A rule that is switched off.
rules:
  - id: test.off
    title: Off
    category: test
    risk: blocked
    decision: deny
    reason: test
    enabled: false
    match: { action: exec, program: [rm] }
"#,
    );
    assert_eq!(set.len(), 0);
    assert_eq!(set.rules().len(), 1);
    assert!(set.rules()[0].disabled);
    let case = exec(&["rm", "-rf", "/"]);
    assert!(set.evaluate(&case.ctx()).matches.is_empty());
}

// ---------------------------------------------------------------------------
// Match predicates
// ---------------------------------------------------------------------------

#[test]
fn ancestor_program_looks_at_every_parent() {
    let set = set_from(
        r#"
version: 1
name: test.ancestry
description: A rule about the parents of a process.
rules:
  - id: test.under-agent
    title: Under an agent
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      program: [rm]
      ancestor_program: [claude, codex]
"#,
    );
    let under_agent = exec(&["rm", "file"]).with_ancestry(&["bash", "make", "claude"]);
    assert_eq!(ids(&set.evaluate(&under_agent.ctx())).len(), 1);

    let under_shell = exec(&["rm", "file"]).with_ancestry(&["bash", "sshd"]);
    assert!(set.evaluate(&under_shell.ctx()).matches.is_empty());

    let alone = exec(&["rm", "file"]);
    assert!(set.evaluate(&alone.ctx()).matches.is_empty());
}

#[test]
fn parent_program_looks_only_at_the_nearest_parent() {
    let set = set_from(
        r#"
version: 1
name: test.parent
description: A rule about the nearest parent.
rules:
  - id: test.under-curl
    title: Under a download tool
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      program: [bash]
      parent_program: [curl]
"#,
    );
    let near = exec(&["bash", "-s"]).with_ancestry(&["curl", "bash"]);
    assert_eq!(ids(&set.evaluate(&near.ctx())).len(), 1);

    let far = exec(&["bash", "-s"]).with_ancestry(&["bash", "curl"]);
    assert!(set.evaluate(&far.ctx()).matches.is_empty());
}

#[test]
fn ancestor_depth_at_least_counts_the_parents() {
    let set = set_from(
        r#"
version: 1
name: test.depth
description: A rule about the depth of a process.
rules:
  - id: test.deep
    title: Deep
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      program: [bash]
      ancestor_depth_at_least: 3
"#,
    );
    let deep = exec(&["bash", "-c", "echo"]).with_ancestry(&["bash", "sh", "claude"]);
    assert_eq!(ids(&set.evaluate(&deep.ctx())).len(), 1);
    let shallow = exec(&["bash", "-c", "echo"]).with_ancestry(&["claude"]);
    assert!(set.evaluate(&shallow.ctx()).matches.is_empty());
}

#[test]
fn not_turns_a_condition_around() {
    let set = set_from(
        r#"
version: 1
name: test.not
description: A rule with a condition that must not hold.
rules:
  - id: test.not-local
    title: Not local
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: network_connect
      port: 5432
      not:
        host_matches: '^localhost$'
"#,
    );
    let remote = connect("db.example.com", "203.0.113.7", 5432);
    assert_eq!(ids(&set.evaluate(&remote.ctx())).len(), 1);
    let local = connect("localhost", "127.0.0.1", 5432);
    assert!(set.evaluate(&local.ctx()).matches.is_empty());
}

#[test]
fn any_of_needs_one_branch_and_all_of_needs_every_branch() {
    let set = set_from(
        r#"
version: 1
name: test.groups
description: Rules that group conditions.
rules:
  - id: test.any
    title: Any
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      any_of:
        - program: [rm]
        - program: [dd]
  - id: test.all
    title: All
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      all_of:
        - program: [rm]
        - argv_contains: ["-r"]
"#,
    );
    let rm = exec(&["rm", "file"]);
    assert_eq!(ids(&set.evaluate(&rm.ctx())), vec!["test.any".to_string()]);

    let dd = exec(&["dd", "if=/dev/zero", "of=out.img"]);
    assert_eq!(ids(&set.evaluate(&dd.ctx())), vec!["test.any".to_string()]);

    let recursive = exec(&["rm", "-r", "dir"]);
    let mut both = ids(&set.evaluate(&recursive.ctx()));
    both.sort();
    assert_eq!(both, vec!["test.all".to_string(), "test.any".to_string()]);

    let other = exec(&["ls", "-l"]);
    assert!(set.evaluate(&other.ctx()).matches.is_empty());
}

#[test]
fn an_exception_switches_a_rule_off_for_one_action() {
    let set = set_from(
        r#"
version: 1
name: test.exception
description: A rule with an exception.
rules:
  - id: test.exception
    title: With an exception
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match:
      action: exec
      program: [git]
      argv_matches: '(?:^|\s)push(?:\s|$)'
    exceptions:
      - argv_any: ["--dry-run"]
"#,
    );
    let real = exec(&["git", "push", "origin", "main"]);
    assert_eq!(
        set.evaluate(&real.ctx()).decision,
        Decision::ApprovalRequired
    );
    let dry = exec(&["git", "push", "--dry-run", "origin", "main"]);
    let verdict = set.evaluate(&dry.ctx());
    assert_eq!(verdict.decision, Decision::Allow);
    assert!(verdict.matches.is_empty());
}

#[test]
fn an_allow_rule_cannot_make_a_deny_rule_weak() {
    let set = set_from(
        r#"
version: 1
name: test.order
description: A strong rule and a weak rule that both match.
rules:
  - id: test.deny
    title: Deny
    category: test
    risk: blocked
    decision: deny
    reason: test
    match: { action: exec, program: [rm] }
  - id: test.allow
    title: Allow
    category: test
    risk: info
    decision: allow
    reason: test
    match: { action: exec, program: [rm] }
"#,
    );
    let case = exec(&["rm", "file"]);
    let verdict = set.evaluate(&case.ctx());
    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(verdict.risk, RiskLevel::Blocked);
    assert_eq!(verdict.matches.len(), 2);
}

#[test]
fn path_and_glob_and_prefix_select_a_file() {
    let set = set_from(
        r#"
version: 1
name: test.paths
description: Rules about a file that a process opens.
rules:
  - id: test.glob
    title: Glob
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: file_open
      write: true
      path_glob: ["**/.ssh/*"]
  - id: test.prefix
    title: Prefix
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: file_open
      path_prefix: ["/etc/"]
  - id: test.exact
    title: Exact
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: file_open
      path: ["/etc/passwd"]
"#,
    );
    let key = file_open("/home/dev/.ssh/id_ed25519", true);
    assert_eq!(ids(&set.evaluate(&key.ctx())), vec!["test.glob".to_string()]);

    let read_key = file_open("/home/dev/.ssh/id_ed25519", false);
    assert!(set.evaluate(&read_key.ctx()).matches.is_empty());

    let passwd = file_open("/etc/passwd", false);
    let mut found = ids(&set.evaluate(&passwd.ctx()));
    found.sort();
    assert_eq!(
        found,
        vec!["test.exact".to_string(), "test.prefix".to_string()]
    );
}

#[test]
fn cwd_prefix_reads_the_working_directory() {
    let set = set_from(
        r#"
version: 1
name: test.cwd
description: A rule that looks at the working directory.
rules:
  - id: test.outside
    title: Outside
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      program: [rm]
      cwd_not_prefix: ["/home/dev/app"]
"#,
    );
    let inside = exec_in("/home/dev/app/src", &["rm", "file"]);
    assert!(set.evaluate(&inside.ctx()).matches.is_empty());
    let outside = exec_in("/var/lib/data", &["rm", "file"]);
    assert_eq!(ids(&set.evaluate(&outside.ctx())).len(), 1);
}

#[test]
fn env_needs_the_name_and_the_value() {
    let set = set_from(
        r#"
version: 1
name: test.env
description: Rules about the environment of a process.
rules:
  - id: test.value
    title: Value
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      env:
        PGHOST: '(?i)prod'
  - id: test.present
    title: Present
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      env:
        CI: ''
"#,
    );
    let prod = exec(&["psql"]).with_env("PGHOST", "prod-db");
    assert_eq!(ids(&set.evaluate(&prod.ctx())), vec!["test.value".to_string()]);

    let dev = exec(&["psql"]).with_env("PGHOST", "dev-db");
    assert!(set.evaluate(&dev.ctx()).matches.is_empty());

    let ci = exec(&["psql"]).with_env("CI", "");
    assert_eq!(
        ids(&set.evaluate(&ci.ctx())),
        vec!["test.present".to_string()]
    );
}

#[test]
fn argv_predicates_read_the_command_line() {
    let set = set_from(
        r#"
version: 1
name: test.argv
description: Rules about the command line.
rules:
  - id: test.contains
    title: Contains
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      argv_contains: ["--force", "origin"]
  - id: test.any
    title: Any
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      argv_any: ["--force", "-f"]
  - id: test.not-matches
    title: Not
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      argv_matches: '(?:^|\s)push(?:\s|$)'
      argv_not_matches: 'force'
"#,
    );
    let force = exec(&["git", "push", "--force", "origin", "main"]);
    let mut found = ids(&set.evaluate(&force.ctx()));
    found.sort();
    assert_eq!(
        found,
        vec!["test.any".to_string(), "test.contains".to_string()]
    );

    let plain = exec(&["git", "push", "origin", "main"]);
    assert_eq!(
        ids(&set.evaluate(&plain.ctx())),
        vec!["test.not-matches".to_string()]
    );
}

#[test]
fn exe_glob_reads_the_program_path() {
    let set = set_from(
        r#"
version: 1
name: test.exe
description: A rule about the path of the program.
rules:
  - id: test.temp
    title: Temp
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      exe_glob: ["/tmp/**"]
"#,
    );
    let temp = exec(&["/tmp/setup"]);
    assert_eq!(ids(&set.evaluate(&temp.ctx())).len(), 1);
    let normal = exec(&["/usr/bin/ls"]);
    assert!(set.evaluate(&normal.ctx()).matches.is_empty());
}

#[test]
fn input_matches_reads_captured_content() {
    let set = set_from(
        r#"
version: 1
name: test.input
description: A rule about content that the monitor captured.
rules:
  - id: test.input
    title: Input
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match:
      action: input
      input_matches: '(?i)\bdrop\s+table\b'
"#,
    );
    let script = exec(&["psql"]).with_input("drop table orders;");
    assert_eq!(
        set.evaluate(&script.ctx()).decision,
        Decision::ApprovalRequired
    );
    let safe = exec(&["psql"]).with_input("select 1;");
    assert!(set.evaluate(&safe.ctx()).matches.is_empty());
    let no_input = exec(&["psql", "-c", "drop table orders"]);
    assert!(set.evaluate(&no_input.ctx()).matches.is_empty());
}

// ---------------------------------------------------------------------------
// Lint and declared tests
// ---------------------------------------------------------------------------

#[test]
fn the_lint_reports_a_rule_that_matches_every_action() {
    let set = set_from(
        r#"
version: 1
name: test.open
description: A rule with no condition.
rules:
  - id: test.open
    title: Open
    category: test
    risk: low
    decision: allow
    reason: test
    match: {}
"#,
    );
    let found = set.lint();
    assert!(found.iter().any(|d| d.severity == Severity::Error
        && d.rule_id == "test.open"
        && d.message.contains("every action")));
}

#[test]
fn the_lint_reports_a_condition_for_the_wrong_action() {
    let set = set_from(
        r#"
version: 1
name: test.mixed
description: A rule that reads a port on a program start.
rules:
  - id: test.mixed
    title: Mixed
    category: test
    risk: low
    decision: allow
    reason: test
    match:
      action: exec
      port: 22
"#,
    );
    let found = set.lint();
    assert!(
        found
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("never match")),
        "{found:?}"
    );
}

#[test]
fn the_lint_reports_a_rule_with_no_test() {
    let set = set_from(
        r#"
version: 1
name: test.untested
description: A rule with no test.
rules:
  - id: test.untested
    title: Untested
    category: test
    risk: low
    decision: allow
    reason: test
    match: { action: exec, program: [rm] }
"#,
    );
    let found = set.lint();
    assert!(found
        .iter()
        .any(|d| d.severity == Severity::Warning && d.message.contains("no test")));
}

#[test]
fn run_tests_reports_the_rule_the_test_and_both_decisions() {
    let set = set_from(
        r#"
version: 1
name: test.failing
description: A rule with a test that does not hold.
rules:
  - id: test.failing
    title: Failing
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: exec, program: [rm] }
    tests:
      - name: a delete is denied
        expect: deny
        process: { pid: 1, comm: rm, exe: /usr/bin/rm, argv: [rm, file] }
"#,
    );
    let report = set.run_tests();
    assert!(!report.is_ok());
    assert_eq!(report.passed, 0);
    assert_eq!(report.failures.len(), 1);
    let failure = &report.failures[0];
    assert_eq!(failure.rule_id, "test.failing");
    assert_eq!(failure.test_name, "a delete is denied");
    assert_eq!(failure.expected, Decision::Deny);
    assert_eq!(failure.actual, Decision::ApprovalRequired);
    assert_eq!(failure.source, "test.yaml");
}


// ---------------------------------------------------------------------------
// Session memory: rule format, load errors and lint
// ---------------------------------------------------------------------------

/// Returns a rule file with one memory block, so a test can change one line.
fn memory_rule(body: &str) -> String {
    format!(
        "version: 1\nname: test.memory\ndescription: A rule with a memory block.\nrules:\n{body}"
    )
}

#[test]
fn a_remember_block_without_a_name_is_a_load_error() {
    let text = memory_rule(
        r#"  - id: test.mark
    title: Mark
    category: test
    risk: info
    decision: allow
    reason: test
    match: { action: exec, program: [cat] }
    remember: { mark: '  ' }
"#,
    );
    let error = PolicySet::from_str(&text, "rules/mark.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("remember.mark"), "{error}");
}

#[test]
fn a_threshold_that_asks_for_one_hit_is_a_load_error() {
    let text = memory_rule(
        r#"  - id: test.count
    title: Count
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: exec, program: [rm] }
    threshold: { window_seconds: 60, at_least: 1 }
"#,
    );
    let error = PolicySet::from_str(&text, "rules/count.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("at_least"), "{error}");
}

#[test]
fn a_threshold_with_no_window_is_a_load_error() {
    let text = memory_rule(
        r#"  - id: test.count
    title: Count
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: exec, program: [rm] }
    threshold: { window_seconds: 0, at_least: 3 }
"#,
    );
    let error = PolicySet::from_str(&text, "rules/count.yaml").expect_err("the load fails");
    assert!(error.to_string().contains("window_seconds"), "{error}");
}

#[test]
fn a_capture_without_exactly_one_group_is_a_load_error() {
    for pattern in ["push\\s+\\S+", "push\\s+(\\S+)\\s+(\\S+)"] {
        let text = memory_rule(&format!(
            r#"  - id: test.baseline
    title: Baseline
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match:
      action: exec
      baseline_missing: {{ set: git_remotes, capture: '{pattern}' }}
"#
        ));
        let error = PolicySet::from_str(&text, "rules/base.yaml").expect_err("the load fails");
        assert!(
            error.to_string().contains("exactly one group"),
            "{pattern}: {error}"
        );
    }
}

#[test]
fn a_mark_that_no_rule_remembers_is_a_lint_error() {
    let text = memory_rule(
        r#"  - id: test.chain
    title: Chain
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match:
      action: exec
      program: [curl]
      marked: { mark: credentail-read }
    tests:
      - name: it matches
        expect: approval_required
        process: { pid: 1, comm: curl, argv: [curl, -T, x, "https://h/"] }
"#,
    );
    let set = PolicySet::from_str(&text, "rules/chain.yaml").expect("the rule loads");
    let diagnostics = set.lint();
    assert!(
        diagnostics.iter().any(|d| d.severity == Severity::Error
            && d.message.contains("credentail-read")
            && d.message.contains("no loaded rule remembers it")),
        "{diagnostics:?}"
    );
}

#[test]
fn a_count_over_paths_in_an_exec_rule_is_a_lint_error() {
    let text = memory_rule(
        r#"  - id: test.sweep
    title: Sweep
    category: test
    risk: approval_required
    decision: approval_required
    reason: test
    match: { action: exec, program: [cat] }
    threshold: { window_seconds: 60, at_least: 3, distinct: path }
"#,
    );
    let set = PolicySet::from_str(&text, "rules/sweep.yaml").expect("the rule loads");
    let diagnostics = set.lint();
    assert!(
        diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("can never count")),
        "{diagnostics:?}"
    );
}

#[test]
fn a_rule_that_asks_for_a_mark_stays_quiet_without_a_memory() {
    let set = PolicySet::builtin().expect("the built-in pack loads");
    let case = exec(&["curl", "-T", "report.txt", "https://files.example.com/u"]);
    let verdict = set.evaluate(&case.ctx());
    assert!(
        !ids(&verdict).contains(&"memory.exfil.after-credential-read".to_string()),
        "{:?}",
        ids(&verdict)
    );
}
