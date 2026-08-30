//! The answer mode of the approver.

use crate::console;

/// How the firewall answers a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Ask the user on the terminal.
    Ask,
    /// Answer every question with allow. Use it only for tests and
    /// demonstrations.
    AutoAllow,
    /// Answer every question with deny. This is the safe answer when nobody
    /// can answer.
    AutoDeny,
}

impl ApprovalMode {
    /// Reads a mode from text: `ask`, `allow` or `deny`.
    ///
    /// The function removes spaces at the two ends and ignores the letter
    /// case. It returns `None` for every other word.
    pub fn parse(text: &str) -> Option<ApprovalMode> {
        match text.trim().to_ascii_lowercase().as_str() {
            "ask" => Some(ApprovalMode::Ask),
            "allow" => Some(ApprovalMode::AutoAllow),
            "deny" => Some(ApprovalMode::AutoDeny),
            _ => None,
        }
    }

    /// Returns `Ask` when a terminal is available and `AutoDeny` when it is
    /// not.
    ///
    /// The function opens `/dev/tty` to test the terminal. A
    /// continuous-integration job has no terminal, so it gets the safe mode.
    pub fn automatic() -> ApprovalMode {
        if console::terminal_is_available() {
            ApprovalMode::Ask
        } else {
            ApprovalMode::AutoDeny
        }
    }

    /// Returns the name of the mode for logs and for the user interface.
    ///
    /// The name is the same word that [`ApprovalMode::parse`] reads.
    pub fn label(&self) -> &'static str {
        match self {
            ApprovalMode::Ask => "ask",
            ApprovalMode::AutoAllow => "allow",
            ApprovalMode::AutoDeny => "deny",
        }
    }
}

impl std::fmt::Display for ApprovalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_the_three_words() {
        assert_eq!(ApprovalMode::parse("ask"), Some(ApprovalMode::Ask));
        assert_eq!(ApprovalMode::parse("allow"), Some(ApprovalMode::AutoAllow));
        assert_eq!(ApprovalMode::parse("deny"), Some(ApprovalMode::AutoDeny));
    }

    #[test]
    fn parse_ignores_spaces_and_letter_case() {
        assert_eq!(ApprovalMode::parse("  Ask "), Some(ApprovalMode::Ask));
        assert_eq!(ApprovalMode::parse("DENY"), Some(ApprovalMode::AutoDeny));
    }

    #[test]
    fn parse_refuses_every_other_word() {
        for text in [
            "",
            " ",
            "a",
            "yes",
            "auto",
            "auto-allow",
            "terminate",
            "ask deny",
        ] {
            assert_eq!(ApprovalMode::parse(text), None, "text: {text:?}");
        }
    }

    #[test]
    fn the_label_is_the_word_that_parse_reads() {
        for mode in [
            ApprovalMode::Ask,
            ApprovalMode::AutoAllow,
            ApprovalMode::AutoDeny,
        ] {
            assert_eq!(ApprovalMode::parse(mode.label()), Some(mode));
            assert_eq!(mode.to_string(), mode.label());
        }
    }
}
