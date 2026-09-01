//! An approver that answers from a list.
//!
//! A test of the monitor needs an answer without a user and without a
//! terminal. This approver gives that answer, and it keeps the text of every
//! question. A test can then prove that the user sees the right explanation.

use std::collections::VecDeque;

use af_core::{ApprovalOutcome, ApprovalRequest, Approver};

use crate::prompt::render_prompt;

/// An approver for tests. It answers from a list.
///
/// The approver takes the answers in order. When the list is empty, the
/// approver denies, because deny is the safe answer.
#[derive(Debug, Default)]
pub struct ScriptedApprover {
    /// The answers that the approver did not use yet.
    answers: VecDeque<ApprovalOutcome>,
    /// The text of every question that the approver received.
    seen: Vec<String>,
}

impl ScriptedApprover {
    /// Makes an approver that gives these answers, first answer first.
    pub fn new(answers: Vec<ApprovalOutcome>) -> Self {
        Self {
            answers: answers.into(),
            seen: Vec::new(),
        }
    }

    /// Returns every request that the approver received, as rendered text.
    ///
    /// The text is the text of [`render_prompt`] without colour.
    pub fn seen(&self) -> &[String] {
        &self.seen
    }

    /// Returns how many answers the approver did not use yet.
    pub fn remaining(&self) -> usize {
        self.answers.len()
    }
}

impl Approver for ScriptedApprover {
    fn request(&mut self, req: &ApprovalRequest<'_>) -> ApprovalOutcome {
        self.seen.push(render_prompt(req, false, None));
        self.answers.pop_front().unwrap_or(ApprovalOutcome::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn the_answers_come_in_order() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let mut approver = ScriptedApprover::new(vec![
            ApprovalOutcome::Allow,
            ApprovalOutcome::AllowForSession,
            ApprovalOutcome::TerminateSession,
        ]);

        assert_eq!(approver.remaining(), 3);
        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Allow);
        assert_eq!(
            approver.request(&fixture.request()),
            ApprovalOutcome::AllowForSession
        );
        assert_eq!(
            approver.request(&fixture.request()),
            ApprovalOutcome::TerminateSession
        );
        assert_eq!(approver.remaining(), 0);
    }

    #[test]
    fn an_empty_list_denies() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let mut approver = ScriptedApprover::new(Vec::new());
        assert_eq!(approver.request(&fixture.request()), ApprovalOutcome::Deny);
        assert_eq!(approver.seen().len(), 1);
    }

    #[test]
    fn the_approver_keeps_the_text_of_every_question() {
        let first = Fixture::psql("DROP DATABASE a");
        let second = Fixture::psql("DROP DATABASE b");
        let mut approver = ScriptedApprover::new(vec![ApprovalOutcome::Deny; 2]);

        approver.request(&first.request());
        approver.request(&second.request());

        let seen = approver.seen();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("DROP DATABASE a"), "{}", seen[0]);
        assert!(seen[1].contains("DROP DATABASE b"), "{}", seen[1]);
        assert!(
            seen[0].contains("database.destructive.drop-database"),
            "{}",
            seen[0]
        );
        assert!(!seen[0].contains('\u{1b}'), "the text holds colour");
    }
}
