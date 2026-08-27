//! Provenance of one monitored session.
//!
//! The firewall must answer one question before it stops an action: where
//! did this action come from? A flat list of commands cannot answer it. This
//! crate therefore builds a causal graph of the processes of one session:
//!
//! ```text
//! user session
//!   -> coding agent
//!     -> shell tool
//!       -> bash
//!         -> script
//!           -> psql
//! ```
//!
//! [`ProcessGraph`] reads the normalized events of [`af_core`] and keeps the
//! whole tree. It works live, and it works again later on a recorded trace,
//! so a policy test gives the same chain as the real session.
//!
//! # Rules of the graph
//!
//! * The graph never removes a process. A parent shell often ends before the
//!   user looks at a child, but the chain must still reach the session root.
//! * The graph keys the nodes on [`af_core::ProcessKey`]. Linux gives the
//!   same identifier to a new process later, and the start time keeps the two
//!   processes apart.
//! * An exec updates a node. It does not make a new one, because a process
//!   keeps its identity when it replaces its program.
//! * A process with an unknown parent hangs under the session root. The graph
//!   counts such a case as a gap and reports it with
//!   [`ProcessGraph::gap_count`].
//!
//! # Example
//!
//! ```
//! use af_core::{Event, EventKind, ProcessInfo, SessionMeta};
//! use af_provenance::ProcessGraph;
//!
//! let mut session = SessionMeta::new(vec!["claude".to_string()], "/work".to_string());
//! session.root_pid = 1000;
//! session.session_id = af_core::SessionId::from("afw-1a2b");
//!
//! let mut graph = ProcessGraph::new(&session);
//! graph.apply(&Event::new(
//!     session.session_id.clone(),
//!     0,
//!     EventKind::SessionStart {
//!         meta: Box::new(session.clone()),
//!         capabilities: Vec::new(),
//!     },
//! ));
//! graph.apply(&Event::new(
//!     session.session_id.clone(),
//!     1000,
//!     EventKind::ProcessFork {
//!         child_pid: 1001,
//!         is_thread: false,
//!     },
//! ));
//! graph.apply(&Event::new(
//!     session.session_id.clone(),
//!     1001,
//!     EventKind::ProcessExec {
//!         process: Box::new(ProcessInfo {
//!             pid: 1001,
//!             ppid: Some(1000),
//!             comm: "bash".to_string(),
//!             argv: vec!["bash".to_string()],
//!             ..Default::default()
//!         }),
//!     },
//! ));
//!
//! assert_eq!(graph.len(), 2);
//! assert_eq!(graph.chain_summary(1001), "claude[1000] -> bash[1001]");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod graph;
mod node;
mod render;

pub use graph::ProcessGraph;
pub use node::ExitStatus;
