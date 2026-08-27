//! A small pattern matcher for paths.
//!
//! The firewall does not add a glob crate for this. The rule format needs
//! only three wildcards:
//!
//! * `?` matches one character, but not a path separator;
//! * `*` matches any number of characters, but not a path separator;
//! * `**` matches any number of characters, and also path separators.
//!
//! A pattern is compiled one time when the firewall loads the rules. The
//! match itself makes no allocation, because a held process waits while the
//! engine runs.

/// One part of a compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// One exact character.
    Literal(char),
    /// One character that is not a path separator.
    AnyChar,
    /// Any text inside one path part.
    AnyInPart,
    /// Any text, over any number of path parts.
    AnyParts,
}

/// A compiled path pattern.
#[derive(Debug, Clone)]
pub struct Glob {
    pattern: String,
    tokens: Vec<Token>,
    /// True when the pattern holds no wildcard. The match is then a compare.
    plain: bool,
}

impl Glob {
    /// Compiles a pattern.
    ///
    /// The function never fails. Every character that is not a wildcard is an
    /// exact character.
    pub fn new(pattern: &str) -> Self {
        let mut tokens: Vec<Token> = Vec::new();
        let mut chars = pattern.chars().peekable();
        while let Some(ch) = chars.next() {
            let token = match ch {
                '?' => Token::AnyChar,
                '*' => {
                    if chars.peek() == Some(&'*') {
                        while chars.peek() == Some(&'*') {
                            chars.next();
                        }
                        Token::AnyParts
                    } else {
                        Token::AnyInPart
                    }
                }
                other => Token::Literal(other),
            };
            // Two stars beside each other are the same as the stronger one.
            match (tokens.last(), &token) {
                (Some(Token::AnyParts), Token::AnyParts | Token::AnyInPart) => continue,
                (Some(Token::AnyInPart), Token::AnyParts) => {
                    tokens.pop();
                }
                (Some(Token::AnyInPart), Token::AnyInPart) => continue,
                _ => {}
            }
            tokens.push(token);
        }
        let plain = tokens.iter().all(|t| matches!(t, Token::Literal(_)));
        Self {
            pattern: pattern.to_string(),
            tokens,
            plain,
        }
    }

    /// Returns true when the pattern matches the whole text.
    pub fn matches(&self, text: &str) -> bool {
        if self.plain {
            return self.pattern == text;
        }
        match_tokens(&self.tokens, text)
    }
}

/// Matches a token list against text.
///
/// The function walks the tokens from left to right. A star tries the
/// shortest text first and then longer text, so the match is deterministic.
fn match_tokens(tokens: &[Token], text: &str) -> bool {
    let Some(token) = tokens.first() else {
        return text.is_empty();
    };
    let rest_tokens = &tokens[1..];
    match token {
        Token::Literal(expected) => match text.chars().next() {
            Some(ch) if ch == *expected => match_tokens(rest_tokens, &text[ch.len_utf8()..]),
            _ => false,
        },
        Token::AnyChar => match text.chars().next() {
            Some(ch) if ch != '/' => match_tokens(rest_tokens, &text[ch.len_utf8()..]),
            _ => false,
        },
        Token::AnyInPart => walk(rest_tokens, text, false),
        Token::AnyParts => walk(rest_tokens, text, true),
    }
}

/// Tries every length that a star can take.
///
/// `over_parts` is true for `**`, which may also step over a separator.
fn walk(rest_tokens: &[Token], text: &str, over_parts: bool) -> bool {
    let mut left = text;
    loop {
        if match_tokens(rest_tokens, left) {
            return true;
        }
        match left.chars().next() {
            Some(ch) if over_parts || ch != '/' => left = &left[ch.len_utf8()..],
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Glob;

    #[test]
    fn plain_pattern_is_an_exact_compare() {
        let glob = Glob::new("/usr/bin/psql");
        assert!(glob.matches("/usr/bin/psql"));
        assert!(!glob.matches("/usr/bin/psql2"));
        assert!(!glob.matches("/usr/local/bin/psql"));
    }

    #[test]
    fn one_star_stays_inside_one_path_part() {
        let glob = Glob::new("/tmp/*");
        assert!(glob.matches("/tmp/run.sh"));
        assert!(!glob.matches("/tmp/a/run.sh"));
    }

    #[test]
    fn two_stars_step_over_path_parts() {
        let glob = Glob::new("/tmp/**");
        assert!(glob.matches("/tmp/run.sh"));
        assert!(glob.matches("/tmp/a/b/run.sh"));
        assert!(!glob.matches("/var/tmp/run.sh"));
    }

    #[test]
    fn a_question_mark_matches_one_character() {
        let glob = Glob::new("/dev/sd?");
        assert!(glob.matches("/dev/sda"));
        assert!(!glob.matches("/dev/sdab"));
        assert!(!glob.matches("/dev/sd/a"));
    }

    #[test]
    fn two_stars_in_the_middle_find_a_home_directory() {
        let glob = Glob::new("**/.aws/credentials");
        assert!(glob.matches("/home/dev/.aws/credentials"));
        assert!(glob.matches("/root/.aws/credentials"));
        assert!(!glob.matches("/home/dev/.aws/config"));
    }

    #[test]
    fn a_star_at_the_end_can_match_nothing() {
        let glob = Glob::new("mkfs*");
        assert!(glob.matches("mkfs"));
        assert!(glob.matches("mkfs.ext4"));
    }

    #[test]
    fn text_after_the_pattern_does_not_match() {
        let glob = Glob::new("/etc/*");
        assert!(!glob.matches("/etc"));
        assert!(glob.matches("/etc/passwd"));
    }
}
