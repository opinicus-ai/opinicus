use std::collections::{BTreeMap, BTreeSet};

use af_core::{Decision, PolicyEngine};
use af_policy::PolicySet;

#[test]
fn builtin_pack_loads_lints_clean_and_passes_its_tests() {
    let set = PolicySet::builtin().expect("the built-in pack loads");
    let diagnostics = set.lint();
    assert!(
        diagnostics.is_empty(),
        "lint found problems:\n{}",
        diagnostics
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
    let report = set.run_tests();
    assert!(
        report.is_ok(),
        "{report}\n{}",
        report
            .failures
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
    println!("{} rules, {report}", set.len());
}

#[test]
fn the_pack_asks_for_a_decision_only_on_a_small_part_of_the_rules() {
    let set = PolicySet::builtin().expect("the built-in pack loads");
    let rules = set.rules();

    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_decision: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_risk: BTreeMap<String, usize> = BTreeMap::new();
    for rule in &rules {
        *per_file.entry(rule.source.clone()).or_default() += 1;
        *per_decision
            .entry(format!("{:?}", rule.decision))
            .or_default() += 1;
        *per_risk.entry(format!("{:?}", rule.risk)).or_default() += 1;
    }

    let stops = rules
        .iter()
        .filter(|r| r.decision >= Decision::ApprovalRequired)
        .count();
    let quiet = rules.len() - stops;

    println!("rules per file: {per_file:?}");
    println!("rules per decision: {per_decision:?}");
    println!("rules per risk: {per_risk:?}");
    println!("{stops} rules stop the action, {quiet} rules only report");

    assert_eq!(stops + quiet, rules.len());
    assert!(
        quiet * 2 >= stops,
        "too many rules stop the action: {stops} of {}",
        rules.len()
    );
    assert!(
        rules.iter().all(|r| r.decision != Decision::Terminate),
        "the built-in pack never ends a session by itself"
    );
}

#[test]
fn every_category_of_the_specification_has_rules() {
    let set = PolicySet::builtin().expect("the built-in pack loads");
    let categories: BTreeSet<String> = set.rules().into_iter().map(|r| r.category).collect();
    for wanted in [
        "filesystem",
        "git",
        "database",
        "cloud",
        "network",
        "process",
        "allowlist",
    ] {
        assert!(
            categories.contains(wanted),
            "the pack has no rule of the category `{wanted}`"
        );
    }
}
