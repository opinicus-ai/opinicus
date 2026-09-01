//! Redaction and pseudonymization of everything a sample can carry.
//!
//! The monitor already redacts environment values by pattern: it keeps only
//! allow-listed names, and replaces the value of any name that holds
//! `PASSWORD`, `PASSWD`, `TOKEN`, `SECRET`, `KEY`, `CREDENTIAL` or `AUTH`
//! with `<redacted>` ([RESEARCH.md §4]). That pattern, generalized, governs
//! every free text of a sample: a command line, the content of standard
//! input, the evidence line of a sensed fact. On top of it, the identifiers
//! that name the **user** — the home directory, the login in a path, the
//! host name, raw process identifiers, the session identifier, absolute
//! time — are pseudonymized, because a sample is written for a researcher
//! who needs the shape of an event and not the name of a machine.
//!
//! The matcher errs toward redaction. A word that merely contains a marker
//! (`keyboard`, `keynote`) redacts too; a value cut by the cap carries a
//! marker. A sample that redacts too much is a smaller sample. A sample
//! that leaks a credential is a product failure.
//!
//! [RESEARCH.md §4]: https://github.com/opinicus-ai/opinicus/blob/main/docs/RESEARCH.md

use std::collections::BTreeMap;

use af_core::Pid;

use crate::sha256;

/// Text that replaces a secret.
pub const REDACTED: &str = "<redacted>";

/// Marker that replaces the home directory in a path or a text.
pub const HOME: &str = "<home>";

/// Marker that replaces a login name in a path.
pub const USER: &str = "<user>";

/// Marker that replaces the host name in a text.
pub const HOST: &str = "<host>";

/// Word parts that mark a name as a secret. The monitor's list, unchanged.
const SECRET_MARKERS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "SECRET",
    "KEY",
    "CREDENTIAL",
    "AUTH",
];

/// Prefixes of well-known credential shapes. A value that starts with one of
/// these is a secret on its own, with no assignment around it.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "xox",
    "AKIA",
];

/// Words that name an authentication scheme. `Authorization: Bearer <token>`
/// must lose the token, not the scheme word alone.
const SCHEME_WORDS: &[&str] = &["bearer", "token", "basic"];

/// Returns true when a name holds a secret marker, case-insensitively.
///
/// This is the monitor's rule for environment names, applied to any name:
/// `TOKEN`, `api_key`, `DbPassword` all match. A name that merely contains
/// the marker (`keyboard`) matches too — the rule errs toward redaction.
pub fn looks_like_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
}

/// Redacts the secret shapes out of one free text.
///
/// Three shapes are handled:
///
/// * an assignment whose name holds a secret marker keeps its name and
///   loses its value: `password=hunter2` becomes `password=<redacted>`,
///   exactly as the monitor treats an environment value;
/// * a credential that carries its own well-known prefix (`AKIA…`, `ghp_…`,
///   `xox…`, `sk-…` followed by at least eight word characters) is swallowed
///   whole, because the prefix is part of the secret;
/// * nothing else. Ordinary text, paths and URLs without credentials stay.
pub fn redact_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;

    while index < bytes.len() {
        let rest = &text[index..];
        if let Some(consumed) = token_prefix_len(rest) {
            out.push_str(REDACTED);
            index += consumed;
            continue;
        }
        if let Some((value_start, consumed)) = assignment_span(rest) {
            out.push_str(&rest[..value_start]);
            out.push_str(REDACTED);
            index += consumed;
            continue;
        }
        let character = rest.chars().next().expect("a character remains");
        out.push(character);
        index += character.len_utf8();
    }
    out
}

/// Returns how many bytes of a credential with a known prefix to swallow,
/// or `None` when the text does not start with one.
fn token_prefix_len(text: &str) -> Option<usize> {
    for prefix in TOKEN_PREFIXES {
        let Some(rest) = text.strip_prefix(prefix) else {
            continue;
        };
        let value: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if value.chars().count() >= 8 {
            return Some(prefix.len() + value.len());
        }
    }
    None
}

/// Returns where the secret value of an assignment begins and where the
/// assignment ends, or `None` when the text does not start with one.
///
/// The name part may hold letters, digits, separators and spaces, so
/// `Authorization: Bearer <token>` and `db password = hunter2` both match.
/// A scheme word after the separator pulls the credential behind it into
/// the replacement; the name and the scheme word stay.
fn assignment_span(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut name_end = 0usize;
    while name_end < bytes.len() {
        let byte = bytes[name_end];
        let part = byte.is_ascii_alphanumeric()
            || byte == b'_'
            || byte == b'-'
            || byte == b' '
            || byte == b'.';
        if !part {
            break;
        }
        name_end += 1;
    }
    let name = &text[..name_end];
    if name.trim().is_empty() || !looks_like_secret_name(name) {
        return None;
    }
    let mut cursor = name_end;
    if cursor >= bytes.len() || (bytes[cursor] != b':' && bytes[cursor] != b'=') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() && (bytes[cursor] == b' ' || bytes[cursor] == b'\t') {
        cursor += 1;
    }
    // A scheme word (`Bearer`, `Basic`) is not the credential; the word
    // behind it is. The value starts behind the scheme word.
    let scheme_text = &text[cursor..];
    for word in SCHEME_WORDS {
        if scheme_text.len() >= word.len()
            && scheme_text[..word.len()].eq_ignore_ascii_case(word)
            && scheme_text[word.len()..].starts_with(' ')
        {
            cursor += word.len();
            while cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor += 1;
            }
            break;
        }
    }
    let value_start = cursor;
    while cursor < bytes.len() {
        // The value is one word of credential characters. A separator
        // (`;`, `&`, `,`, quotes, spaces) ends it and stays visible, so
        // `password=hunter2; DROP` keeps its second half.
        let byte = bytes[cursor];
        let part = byte.is_ascii_alphanumeric()
            || byte == b'_'
            || byte == b'-'
            || byte == b'.'
            || byte == b'/'
            || byte == b'+'
            || byte == b'='
            || byte == b':'
            || byte == b'@'
            || byte == b'~';
        if !part {
            break;
        }
        cursor += 1;
    }
    if cursor == value_start {
        return None;
    }
    Some((value_start, cursor))
}

/// Cuts a text to a maximum length of characters, with a visible marker.
pub fn cap(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let cut: String = text.chars().take(max_chars).collect();
    format!("{cut}…<cut>")
}

/// The pseudonyms of one packaging run.
///
/// One instance serves a whole trace, so the same process keeps the same
/// reference in every sample of the run. The mappings are deterministic:
/// process references count in order of first appearance, the session
/// reference is a truncated hash of the session identifier, so two packaging
/// runs of one trace name everything alike.
pub struct Pseudonyms {
    home: Option<String>,
    host: Option<String>,
    sessions: BTreeMap<String, String>,
    pids: BTreeMap<Pid, String>,
}

impl Pseudonyms {
    /// Makes pseudonyms for one machine, named by its home directory and its
    /// host name. Either may be unknown.
    pub fn new(home: Option<&str>, host: Option<&str>) -> Self {
        Self {
            home: home.map(|value| value.to_string()),
            host: host.map(|value| value.to_string()),
            sessions: BTreeMap::new(),
            pids: BTreeMap::new(),
        }
    }

    /// Reads the home directory and the host name of this machine.
    ///
    /// The host name comes from `/proc/sys/kernel/hostname`, which needs no
    /// privilege and no library. A machine that hides both leaves them
    /// unknown, and the pseudonymization simply has nothing to replace.
    pub fn from_environment() -> Self {
        let home = std::env::var("HOME").ok().filter(|value| !value.is_empty());
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self::new(home.as_deref(), host.as_deref())
    }

    /// Returns the stable reference of a session identifier.
    ///
    /// The reference is a truncated SHA-256 of the identifier: two samples of
    /// one session share it, and nobody can read the machine's session
    /// identifier back out of it.
    pub fn session(&mut self, session_id: &str) -> String {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| {
                let hash = sha256::hex(&sha256::digest(session_id.as_bytes()));
                format!("s-{}", &hash[..12])
            })
            .clone()
    }

    /// Returns the stable reference of a process identifier: `p1`, `p2`, …
    pub fn pid(&mut self, pid: Pid) -> String {
        if let Some(reference) = self.pids.get(&pid) {
            return reference.clone();
        }
        let reference = format!("p{}", self.pids.len() + 1);
        self.pids.insert(pid, reference.clone());
        reference
    }

    /// Returns the stable reference of a process identifier, when there is
    /// one.
    pub fn maybe_pid(&mut self, pid: Option<Pid>) -> Option<String> {
        pid.map(|pid| self.pid(pid))
    }

    /// Pseudonymizes a path.
    ///
    /// The home directory becomes `<home>`, and any login under `/home` or
    /// `/Users` becomes `<user>`, so a path of another user's tree keeps its
    /// depth and its file names without naming anybody. Everything else —
    /// the directories, the file names, the extensions — stays, because the
    /// rules of the research pipeline match on them.
    pub fn path(&self, path: &str) -> String {
        let mut out = self.text(path);
        out = replace_login_prefix(&out, "/home/");
        out = replace_login_prefix(&out, "/Users/");
        out
    }

    /// Pseudonymizes a free text: the home directory and the host name are
    /// replaced wherever they appear.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_string();
        if let Some(home) = &self.home {
            out = out.replace(home.as_str(), HOME);
        }
        if let Some(host) = &self.host {
            out = out.replace(host.as_str(), HOST);
        }
        out
    }

    /// Redacts and pseudonymizes a free text in one pass.
    pub fn scrub(&self, text: &str) -> String {
        self.text(&redact_text(text))
    }
}

/// Replaces the first path component after `/home/` or `/Users/` with
/// `<user>`, whatever the login is.
fn replace_login_prefix(path: &str, root: &str) -> String {
    let Some(rest) = path.strip_prefix(root) else {
        return path.to_string();
    };
    let Some((login, tail)) = rest.split_once('/') else {
        return path.to_string();
    };
    if login.is_empty() || login.contains('/') {
        return path.to_string();
    }
    format!("{root}{USER}/{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_name_is_found_case_insensitively_and_by_fragment() {
        assert!(looks_like_secret_name("TOKEN"));
        assert!(looks_like_secret_name("api_key"));
        assert!(looks_like_secret_name("DbPassword"));
        assert!(looks_like_secret_name("AUTHORIZATION"));
        assert!(!looks_like_secret_name("path"));
        // The matcher errs toward redaction: a word that contains a marker
        // is treated as a secret name.
        assert!(looks_like_secret_name("keyboard"));
    }

    #[test]
    fn assignments_with_secret_names_lose_their_value() {
        assert_eq!(redact_text("password=hunter2"), "password=<redacted>");
        assert_eq!(redact_text("TOKEN: abc123"), "TOKEN: <redacted>");
        assert_eq!(
            redact_text("psql --set=db_password=hunter2 -c SELECT 1"),
            "psql --set=db_password=<redacted> -c SELECT 1"
        );
        assert_eq!(
            redact_text("the db password is quiet"),
            "the db password is quiet",
            "no assignment shape, no redaction"
        );
    }

    #[test]
    fn an_authorization_header_loses_the_credential_not_the_scheme() {
        assert_eq!(
            redact_text("Authorization: Bearer abc123def456"),
            "Authorization: Bearer <redacted>"
        );
        assert_eq!(
            redact_text("authorization: basic dXNlcjpwYXNz"),
            "authorization: basic <redacted>"
        );
    }

    #[test]
    fn credentials_with_known_prefixes_are_swallowed_whole() {
        assert_eq!(redact_text("ghp_16C7e42F292c6912"), REDACTED);
        assert_eq!(redact_text("xoxb-1234567890-abcdef"), REDACTED);
        assert_eq!(redact_text("AKIAIOSFODNN7EXAMPLE"), REDACTED);
        assert_eq!(redact_text("sk-ant-api03-9a1b2c3d4e5f67890123"), REDACTED);
        // Too short to be a credential: the prefix alone is a word.
        assert_eq!(redact_text("sk-12345"), "sk-12345");
        // No marker, no prefix: ordinary text stays.
        assert_eq!(
            redact_text("DROP DATABASE customer_prod"),
            "DROP DATABASE customer_prod"
        );
    }

    #[test]
    fn redaction_is_multiplicative_over_a_text() {
        let input = "run with password=hunter2 and token=abc123def456ghi789";
        assert_eq!(
            redact_text(input),
            "run with password=<redacted> and token=<redacted>"
        );
    }

    #[test]
    fn the_cap_cuts_at_characters_and_marks_the_cut() {
        assert_eq!(cap("short", 10), "short");
        let long = "x".repeat(20);
        assert_eq!(cap(&long, 10), format!("{}…<cut>", "x".repeat(10)));
    }

    #[test]
    fn paths_lose_the_home_directory_and_the_login_not_the_files() {
        let pseu = Pseudonyms::new(Some("/home/dev"), Some("box1"));
        assert_eq!(
            pseu.path("/home/dev/proj/src/main.rs"),
            "<home>/proj/src/main.rs"
        );
        assert_eq!(
            pseu.path("/home/someoneelse/.ssh/id_ed25519"),
            "/home/<user>/.ssh/id_ed25519"
        );
        assert_eq!(pseu.path("/Users/anna/app"), "/Users/<user>/app");
        assert_eq!(pseu.path("/tmp/build/script.sh"), "/tmp/build/script.sh");
    }

    #[test]
    fn a_text_loses_the_host_name() {
        let pseu = Pseudonyms::new(Some("/home/dev"), Some("box1"));
        assert_eq!(
            pseu.text("connect to box1.internal:5432"),
            "connect to <host>.internal:5432"
        );
        assert_eq!(
            pseu.text("error on box1 while building"),
            "error on <host> while building"
        );
    }

    #[test]
    fn process_references_are_stable_and_ordered_by_first_appearance() {
        let mut pseu = Pseudonyms::new(None, None);
        assert_eq!(pseu.pid(41201), "p1");
        assert_eq!(pseu.pid(41244), "p2");
        assert_eq!(pseu.pid(41201), "p1", "the same pid keeps its reference");
        assert_eq!(pseu.pid(1), "p3");
    }

    #[test]
    fn a_session_reference_is_stable_and_hides_the_identifier() {
        let mut first = Pseudonyms::new(None, None);
        let mut second = Pseudonyms::new(None, None);
        let reference = first.session("afw-18f2a6c1e0b2-2b1");
        assert_eq!(second.session("afw-18f2a6c1e0b2-2b1"), reference);
        assert!(reference.starts_with("s-"));
        assert_eq!(reference.len(), 14);
        assert!(!reference.contains("afw"));
        assert_ne!(first.session("afw-other"), reference);
    }

    #[test]
    fn scrub_combines_redaction_and_pseudonymization() {
        let pseu = Pseudonyms::new(Some("/home/dev"), None);
        assert_eq!(
            pseu.scrub("cat /home/dev/.aws/credentials with password=hunter2"),
            "cat <home>/.aws/credentials with password=<redacted>"
        );
    }
}
