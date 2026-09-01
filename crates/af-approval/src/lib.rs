//! Interactive approval handling for the Agent Firewall.
//!
//! The firewall holds a dangerous action and asks the user what to do. A
//! monitored process waits during that question, so the answer must come
//! fast and the question must be clear.
//!
//! # The terminal
//!
//! The monitored agent owns the standard input of the terminal. This crate
//! therefore never reads the standard input. It opens `/dev/tty`, which is a
//! second path to the same terminal. When the machine has no terminal, for
//! example in a continuous-integration job, the approver does not wait. It
//! writes a warning to standard error and gives the safe answer, which is
//! [`af_core::ApprovalOutcome::Deny`].
//!
//! # Parts
//!
//! * [`TerminalApprover`] asks the user and counts the answers.
//! * [`ApprovalMode`] selects between a question and a fixed answer.
//! * [`SessionMemory`] remembers an answer that holds for the whole session.
//! * [`render_prompt`] draws the question.
//! * [`ScriptedApprover`] answers from a list. Tests use it.
//!
//! # Example
//!
//! ```no_run
//! use af_approval::{ApprovalMode, TerminalApprover};
//! use af_core::Approver;
//!
//! let mut approver = TerminalApprover::new(ApprovalMode::automatic())
//!     .with_timeout(Some(std::time::Duration::from_secs(60)));
//! // The monitor calls `approver.request(&request)` for every held action.
//! # let _ = &mut approver;
//! ```

#![deny(missing_docs)]

mod console;
mod memory;
mod mode;
mod prompt;
mod scripted;
mod terminal;

#[cfg(test)]
mod testing;

pub use memory::SessionMemory;
pub use mode::ApprovalMode;
pub use prompt::{countdown_line, render_prompt};
pub use scripted::ScriptedApprover;
pub use terminal::{ApproverStats, TerminalApprover};
