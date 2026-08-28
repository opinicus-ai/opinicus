//! Risk levels, decisions and the verdict that the policy engine returns.

use serde::{Deserialize, Serialize};

/// How dangerous a matched rule considers an action.
///
/// The order of the variants is the order of severity. `Info` is the lowest
/// level and `Blocked` is the highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Normal development activity. Keep it quiet.
    Info,
    /// Slightly unusual, but not dangerous.
    Low,
    /// Unusual enough to report.
    Suspicious,
    /// The user must decide.
    ApprovalRequired,
    /// The action is never allowed.
    Blocked,
}

impl RiskLevel {
    /// Returns a short label for the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Suspicious => "suspicious",
            RiskLevel::ApprovalRequired => "approval-required",
            RiskLevel::Blocked => "blocked",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// What the firewall does with an action.
///
/// The order of the variants is the order of severity, so the engine can
/// select the strongest decision of all matched rules with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Let the action continue and do not tell the user.
    Allow,
    /// Let the action continue one time only.
    AllowOnce,
    /// Let the action continue for the rest of this session.
    AllowSession,
    /// Hold the action and ask the user.
    ApprovalRequired,
    /// Stop the action, but let the process continue.
    Deny,
    /// Stop the action and end the process tree.
    Terminate,
}

impl Decision {
    /// Returns true when the firewall must hold the action before it runs.
    pub fn needs_intervention(&self) -> bool {
        matches!(
            self,
            Decision::ApprovalRequired | Decision::Deny | Decision::Terminate
        )
    }

    /// Returns a short label for the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::AllowOnce => "allow-once",
            Decision::AllowSession => "allow-session",
            Decision::ApprovalRequired => "approval-required",
            Decision::Deny => "deny",
            Decision::Terminate => "terminate",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One rule that matched an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Stable identifier of the rule, for example
    /// `database.destructive.drop-database`.
    pub rule_id: String,
    /// Short title of the rule.
    pub title: String,
    /// Category of the rule, for example `database` or `git`.
    #[serde(default)]
    pub category: String,
    /// How dangerous the rule considers the action.
    pub risk: RiskLevel,
    /// What the rule wants the firewall to do.
    pub decision: Decision,
    /// Why the rule matched, in words the user can read.
    #[serde(default)]
    pub reason: String,
}

/// The result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// The strongest decision of all matched rules.
    pub decision: Decision,
    /// The highest risk level of all matched rules.
    pub risk: RiskLevel,
    /// Every rule that matched, strongest first.
    #[serde(default)]
    pub matches: Vec<RuleMatch>,
}

impl Verdict {
    /// Returns a verdict that allows the action and matches no rule.
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            risk: RiskLevel::Info,
            matches: Vec::new(),
        }
    }

    /// Makes a verdict from the rules that matched.
    ///
    /// The strongest decision and the highest risk level win. The matches are
    /// sorted with the strongest rule first.
    pub fn from_matches(mut matches: Vec<RuleMatch>) -> Self {
        if matches.is_empty() {
            return Self::allow();
        }
        matches.sort_by(|a, b| {
            b.decision
                .cmp(&a.decision)
                .then(b.risk.cmp(&a.risk))
                .then(a.rule_id.cmp(&b.rule_id))
        });
        let decision = matches.iter().map(|m| m.decision).max().unwrap_or(Decision::Allow);
        let risk = matches.iter().map(|m| m.risk).max().unwrap_or(RiskLevel::Info);
        Self {
            decision,
            risk,
            matches,
        }
    }

    /// Returns the strongest rule that matched, when there is one.
    pub fn top_match(&self) -> Option<&RuleMatch> {
        self.matches.first()
    }

    /// Returns true when the firewall must hold the action.
    pub fn needs_intervention(&self) -> bool {
        self.decision.needs_intervention()
    }
}

impl Default for Verdict {
    fn default() -> Self {
        Self::allow()
    }
}

/// Description of a loaded rule, for `policy list` and for the user interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Stable identifier of the rule.
    pub rule_id: String,
    /// Short title of the rule.
    pub title: String,
    /// Category of the rule.
    #[serde(default)]
    pub category: String,
    /// Risk level of the rule.
    pub risk: RiskLevel,
    /// Decision of the rule.
    pub decision: Decision,
    /// Where the rule came from, for example a file path.
    #[serde(default)]
    pub source: String,
    /// True when the rule is switched off.
    #[serde(default)]
    pub disabled: bool,
    /// The action kinds that the rule can match, for example `file_open`.
    ///
    /// The list is empty when the rule matches any action kind. A monitor that
    /// never makes one of these action kinds can never match the rule, so the
    /// user interface uses this list to report a rule that cannot fire.
    #[serde(default)]
    pub actions: Vec<String>,
    /// True when every file open that the rule matches is an open that reads.
    ///
    /// A monitor can be cheap by letting the kernel drop every open that only
    /// reads, and then such a rule can never fire. The user interface uses
    /// this flag together with [`RuleInfo::actions`] to report it.
    #[serde(default)]
    pub needs_read_open: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, risk: RiskLevel, decision: Decision) -> RuleMatch {
        RuleMatch {
            rule_id: id.to_string(),
            title: id.to_string(),
            category: "test".to_string(),
            risk,
            decision,
            reason: String::new(),
        }
    }

    #[test]
    fn strongest_decision_wins() {
        let verdict = Verdict::from_matches(vec![
            rule("a", RiskLevel::Low, Decision::Allow),
            rule("b", RiskLevel::ApprovalRequired, Decision::ApprovalRequired),
            rule("c", RiskLevel::Suspicious, Decision::AllowSession),
        ]);
        assert_eq!(verdict.decision, Decision::ApprovalRequired);
        assert_eq!(verdict.risk, RiskLevel::ApprovalRequired);
        assert_eq!(verdict.top_match().unwrap().rule_id, "b");
    }

    #[test]
    fn no_match_allows() {
        let verdict = Verdict::from_matches(Vec::new());
        assert_eq!(verdict.decision, Decision::Allow);
        assert!(!verdict.needs_intervention());
    }
}
