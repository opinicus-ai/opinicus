//! Drawing of the process tree.

use af_core::{
    display::{sanitize, truncate},
    Decision,
};

use crate::graph::ProcessGraph;

/// How many characters of the command line the tree shows.
const MAX_ARGS: usize = 60;

impl ProcessGraph {
    /// Draws the whole session as an indented tree.
    ///
    /// The first line names the session. Every other line names one process.
    /// A process carries a mark when the session recorded a decision for it
    /// that is not `allow`.
    ///
    /// The drawing is stable: the same events always give the same text. The
    /// tree sorts the children by creation order and then by process
    /// identifier.
    ///
    /// ```text
    /// afw-1a2b (root)
    /// └─ claude [pid 1000]
    ///    └─ bash -c ./migrate.sh [pid 1001]
    ///       └─ migrate.sh [pid 1002]
    ///          └─ psql -c DROP DATABASE customer_prod [pid 1003]  ✖ approval-required
    /// ```
    pub fn render_tree(&self) -> String {
        let mut out = String::new();
        out.push_str(&sanitize(self.session_id().as_str()));
        out.push_str(" (root)");

        let mut drawn = vec![false; self.len()];
        let roots = self.root_indexes();
        let mut stack: Vec<(usize, String, bool)> = Vec::new();
        push_level(&mut stack, &roots, "");

        while let Some((index, prefix, last)) = stack.pop() {
            if drawn[index] {
                continue;
            }
            drawn[index] = true;
            out.push('\n');
            out.push_str(&prefix);
            out.push_str(if last { "└─ " } else { "├─ " });
            out.push_str(&self.render_label(index));
            let child_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
            let children = self.sorted_children(index);
            push_level(&mut stack, &children, &child_prefix);
        }
        out
    }

    /// Returns the chain of a process as one line, for logs.
    ///
    /// The line starts at the session root and ends at the process:
    ///
    /// ```text
    /// claude[1000] -> bash[1001] -> migrate.sh[1002] -> psql[1003]
    /// ```
    pub fn chain_summary(&self, pid: af_core::Pid) -> String {
        let Some(process) = self.process(pid) else {
            return format!("pid {pid} (unknown)");
        };
        let mut parts: Vec<String> = self.ancestry(pid).iter().rev().map(short_name).collect();
        parts.push(short_name(&process));
        sanitize(&parts.join(" -> "))
    }

    /// Returns the text of one process line.
    fn render_label(&self, index: usize) -> String {
        let node = self.node(index);
        let mut text = String::new();
        for name in &node.history {
            text.push_str(name);
            text.push_str(" -> ");
        }
        let name = node.info.program_name();
        if name.is_empty() {
            text.push_str("(unknown)");
        } else {
            text.push_str(name);
        }
        let args: Vec<&str> = node
            .info
            .argv
            .iter()
            .skip(1)
            .map(|arg| arg.as_str())
            .filter(|arg| !arg.is_empty())
            .collect();
        if !args.is_empty() {
            text.push(' ');
            text.push_str(&truncate(&args.join(" "), MAX_ARGS));
        }
        let mut line = format!("{} [pid {}]", sanitize(&text), node.info.pid);
        if let Some(verdict) = &node.verdict {
            if let Some(mark) = decision_mark(verdict.decision) {
                line.push_str("  ");
                line.push_str(mark);
                line.push(' ');
                line.push_str(verdict.decision.label());
            }
        }
        line
    }
}

/// Puts one level of children on the stack, so that the first child comes
/// out first.
fn push_level(stack: &mut Vec<(usize, String, bool)>, level: &[usize], prefix: &str) {
    for (position, index) in level.iter().enumerate().rev() {
        stack.push((*index, prefix.to_string(), position + 1 == level.len()));
    }
}

/// Returns the mark of a decision, or `None` when the tree stays quiet.
///
/// Normal development activity must stay quiet, so an `allow` gets no mark.
fn decision_mark(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::Allow => None,
        Decision::AllowOnce | Decision::AllowSession => Some("•"),
        Decision::ApprovalRequired | Decision::Deny | Decision::Terminate => Some("✖"),
    }
}

/// Returns the name and the identifier of a process in a short form.
fn short_name(process: &af_core::ProcessInfo) -> String {
    let name = process.program_name();
    if name.is_empty() {
        format!("pid[{}]", process.pid)
    } else {
        format!("{name}[{}]", process.pid)
    }
}
