//! Text that the firewall shows to the user.
//!
//! The approval handler and the command-line interface use the same helpers,
//! so a held action and a recorded trace look the same.

use crate::{
    decision::Verdict,
    process::{Action, ProcessInfo},
};

/// Cuts text to a maximum length and adds an ellipsis.
///
/// The length counts characters, not bytes, so the result is always valid
/// text.
pub fn truncate(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

/// Replaces control characters, so that a program cannot write escape
/// sequences into the terminal of the user.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\n' || c == '\t' {
                ' '
            } else if c.is_control() {
                '·'
            } else {
                c
            }
        })
        .collect()
}

/// Draws the provenance chain from the session root to the acting process.
///
/// `ancestry` must be ordered with the nearest parent first, which is the
/// order that [`crate::ProvenanceView::ancestry`] returns.
///
/// The result looks like this:
///
/// ```text
/// Claude Code
///   -> bash
///     -> migrate.sh
///       -> psql
/// ```
pub fn provenance_chain(ancestry: &[ProcessInfo], process: &ProcessInfo) -> String {
    let mut chain: Vec<&ProcessInfo> = ancestry.iter().rev().collect();
    chain.push(process);

    let mut out = String::new();
    for (depth, node) in chain.iter().enumerate() {
        if depth > 0 {
            out.push('\n');
            for _ in 0..depth {
                out.push_str("  ");
            }
            out.push_str("-> ");
        }
        out.push_str(&sanitize(&describe_process(node)));
    }
    out
}

/// Describes one process in one short line.
fn describe_process(process: &ProcessInfo) -> String {
    let name = process.program_name();
    let name = if name.is_empty() {
        format!("pid {}", process.pid)
    } else {
        name.to_string()
    };
    let interesting_args: Vec<&str> = process
        .argv
        .iter()
        .skip(1)
        .map(|a| a.as_str())
        .filter(|a| !a.is_empty())
        .collect();
    if interesting_args.is_empty() {
        format!("{name} [pid {}]", process.pid)
    } else {
        let args = truncate(&interesting_args.join(" "), 60);
        format!("{name} {args} [pid {}]", process.pid)
    }
}

/// Draws the full explanation of a held or recorded action.
///
/// Every block or question must be explainable, so this text always holds the
/// chain, the operation, the policy and the decision.
pub fn explain(ancestry: &[ProcessInfo], process: &ProcessInfo, action: &Action, verdict: &Verdict) -> String {
    let mut out = String::new();
    out.push_str(&provenance_chain(ancestry, process));
    out.push_str("\nAttempted operation:\n  ");
    out.push_str(&sanitize(&truncate(&action.summary(), 400)));
    match verdict.top_match() {
        Some(rule) => {
            out.push_str("\nPolicy:\n  ");
            out.push_str(&rule.rule_id);
            if !rule.title.is_empty() {
                out.push_str(" — ");
                out.push_str(&rule.title);
            }
            if !rule.reason.is_empty() {
                out.push_str("\nReason:\n  ");
                out.push_str(&sanitize(&rule.reason));
            }
        }
        None => out.push_str("\nPolicy:\n  (no rule matched)"),
    }
    // The user must see every rule that holds this action, and not only the
    // strongest one. A second rule can be the whole reason that the firewall
    // asks again about something that looks like an earlier question.
    let others: Vec<&crate::decision::RuleMatch> = verdict.matches.iter().skip(1).collect();
    if !others.is_empty() {
        out.push_str("\nAlso matched:");
        for rule in others {
            out.push_str("\n  ");
            out.push_str(&rule.rule_id);
            if !rule.title.is_empty() {
                out.push_str(" — ");
                out.push_str(&rule.title);
            }
        }
    }
    out.push_str("\nRisk:\n  ");
    out.push_str(verdict.risk.label());
    out.push_str("\nDecision:\n  ");
    out.push_str(verdict.decision.label());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: i32, name: &str, args: &[&str]) -> ProcessInfo {
        let mut argv = vec![name.to_string()];
        argv.extend(args.iter().map(|a| a.to_string()));
        ProcessInfo {
            pid,
            comm: name.to_string(),
            exe: Some(format!("/usr/bin/{name}")),
            argv,
            ..Default::default()
        }
    }

    #[test]
    fn chain_starts_at_the_session_root() {
        let psql = process(40, "psql", &["-c", "DROP DATABASE x"]);
        let ancestry = vec![
            process(30, "migrate.sh", &[]),
            process(20, "bash", &[]),
            process(10, "claude", &[]),
        ];
        let text = provenance_chain(&ancestry, &psql);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("claude"));
        assert!(lines[1].trim_start().starts_with("-> bash"));
        assert!(lines[3].trim_start().starts_with("-> psql"));
    }

    #[test]
    fn control_characters_do_not_reach_the_terminal() {
        assert_eq!(sanitize("a\u{1b}[31mb"), "a·[31mb");
    }

    #[test]
    fn truncate_keeps_valid_text() {
        assert_eq!(truncate("äöüß", 2), "äö…");
        assert_eq!(truncate("ab", 5), "ab");
    }
}
