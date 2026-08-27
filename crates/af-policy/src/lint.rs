//! Checks that find a rule which cannot work as the author expects.
//!
//! A diagnostic never stops the load. It tells the author about a rule that
//! can never match, a rule with no test, or a risk level that does not agree
//! with the decision.

use af_core::{Decision, RiskLevel};

use crate::matcher::Matcher;
use crate::{CompiledRule, PackInfo};

/// How serious a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The rule works, but something is not as good as it can be.
    Warning,
    /// The rule cannot do what the author wants.
    Error,
}

impl Severity {
    /// Returns a short label for the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One problem in a loaded rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Identifier of the rule that has the problem.
    pub rule_id: String,
    /// Where the rule came from.
    pub source: String,
    /// How serious the problem is.
    pub severity: Severity,
    /// What is wrong, in words the author can read.
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} ({}): {}",
            self.severity, self.rule_id, self.source, self.message
        )
    }
}

/// Checks every rule of a set.
///
/// The result keeps the order of the rules, so two runs give the same list.
pub(crate) fn lint(rules: &[CompiledRule], packs: &[PackInfo]) -> Vec<Diagnostic> {
    let mut out: Vec<Diagnostic> = Vec::new();
    for pack in packs {
        if pack.description.trim().is_empty() {
            out.push(Diagnostic {
                rule_id: pack.name.clone(),
                source: pack.source.clone(),
                severity: Severity::Warning,
                message: "the pack has no description".to_string(),
            });
        }
    }
    for rule in rules {
        check_rule(rule, &mut out);
    }
    out
}

fn check_rule(rule: &CompiledRule, out: &mut Vec<Diagnostic>) {
    let mut add = |severity: Severity, message: String| {
        out.push(Diagnostic {
            rule_id: rule.id.clone(),
            source: rule.source.clone(),
            severity,
            message,
        });
    };

    if rule.matcher.is_open() {
        add(
            Severity::Error,
            "the match has no condition, so the rule matches every action".to_string(),
        );
    }

    let selected = rule.matcher.action();
    let mut problems: Vec<String> = Vec::new();
    rule.matcher.walk(&mut |node: &Matcher| {
        let kind = node.action().or(selected);
        if let Some(kind) = kind {
            for (field, needs) in node.kind_bound_fields() {
                if needs != kind {
                    problems.push(format!(
                        "the field `{field}` needs the action `{}`, but the rule selects `{}`, so it can never match",
                        needs.label(),
                        kind.label()
                    ));
                }
            }
        }
        if node.has_empty_any_of() {
            problems.push("`any_of` holds no condition, so it can never match".to_string());
        }
        if node.has_zero_depth() {
            problems
                .push("`ancestor_depth_at_least: 0` is true for every process".to_string());
        }
    });
    for problem in problems {
        add(Severity::Error, problem);
    }

    for (index, exception) in rule.exceptions.iter().enumerate() {
        if exception.is_open() {
            add(
                Severity::Error,
                format!("exception {index} has no condition, so the rule can never match"),
            );
        }
    }

    if rule.reason.trim().is_empty() {
        add(
            Severity::Warning,
            "the rule has no reason, so the user cannot understand the decision".to_string(),
        );
    }

    if rule.title.trim().is_empty() {
        add(Severity::Warning, "the rule has no title".to_string());
    }

    if rule.category.trim().is_empty() {
        add(Severity::Warning, "the rule has no category".to_string());
    }

    for reference in &rule.references {
        if !reference.starts_with("http://") && !reference.starts_with("https://") {
            add(
                Severity::Warning,
                format!("the reference `{reference}` is not a link"),
            );
        }
    }

    if rule.tests.is_empty() {
        add(
            Severity::Warning,
            "the rule has no test, so nobody proves that it matches".to_string(),
        );
    } else if !rule.tests.iter().any(crate::testing::wants_match) {
        add(
            Severity::Warning,
            "the rule has no test that makes it match; add `expect_match: true` to one test"
                .to_string(),
        );
    }

    for test in &rule.tests {
        if test.expect != Decision::Allow && test.expect != rule.decision {
            add(
                Severity::Error,
                format!(
                    "test `{}` expects `{}`, but the rule decides `{}`",
                    test.name, test.expect, rule.decision
                ),
            );
        }
    }

    if rule.decision.needs_intervention() && rule.risk < RiskLevel::ApprovalRequired {
        add(
            Severity::Warning,
            format!(
                "the decision `{}` stops the action, but the risk level is only `{}`",
                rule.decision, rule.risk
            ),
        );
    }

    if rule.risk >= RiskLevel::ApprovalRequired && !rule.decision.needs_intervention() {
        add(
            Severity::Warning,
            format!(
                "the risk level is `{}`, but the decision `{}` lets the action continue",
                rule.risk, rule.decision
            ),
        );
    }

    if rule.risk == RiskLevel::Blocked && rule.decision == Decision::ApprovalRequired {
        add(
            Severity::Warning,
            "risk `blocked` means that the action is never allowed, so ask for `deny` or `terminate`"
                .to_string(),
        );
    }
}
