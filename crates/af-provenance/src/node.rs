//! One process in the graph.

use af_core::{ProcessInfo, ProcessKey, Verdict};
use serde::{Deserialize, Serialize};

/// How many earlier program names one process keeps.
///
/// A shell can replace its program many times. The graph keeps the first
/// names, because the origin of a chain explains more than the last step.
pub(crate) const MAX_HISTORY: usize = 16;

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExitStatus {
    /// Exit code of the process, when it ended normally.
    pub code: Option<i32>,
    /// Signal that ended the process, when a signal ended it.
    pub signal: Option<i32>,
}

/// One node of the process graph.
///
/// The graph never removes a node. A parent shell often ends before the user
/// looks at a child, but the chain must still reach the session root.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    /// Stable identity of the process.
    pub key: ProcessKey,
    /// Facts about the process.
    pub info: ProcessInfo,
    /// Position of the parent node, or `None` for the session root.
    pub parent: Option<usize>,
    /// Positions of the child nodes, in creation order.
    pub children: Vec<usize>,
    /// Creation order of the node. The first node has number 0.
    pub order: usize,
    /// True when the process is gone.
    pub ended: bool,
    /// How the process ended, when the monitor saw the exit.
    pub exit: Option<ExitStatus>,
    /// Program names that the process used before the current one.
    pub history: Vec<String>,
    /// Strongest verdict that the session recorded for this process.
    pub verdict: Option<Verdict>,
}

impl Node {
    /// Makes a node for a process that the graph did not know before.
    pub fn new(info: ProcessInfo, parent: Option<usize>, order: usize) -> Self {
        Self {
            key: info.key(),
            info,
            parent,
            children: Vec::new(),
            order,
            ended: false,
            exit: None,
            history: Vec::new(),
            verdict: None,
        }
    }

    /// Adds an earlier program name, up to the limit.
    pub fn push_history(&mut self, name: String) {
        if self.history.len() < MAX_HISTORY {
            self.history.push(name);
        }
    }
}
