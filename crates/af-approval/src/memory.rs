//! The memory of the answers that hold for the whole session.
//!
//! The user can answer one question with "allow for this session". The
//! firewall must then let the same action continue again, but it must not let
//! a different action continue. The fingerprint in this module makes that
//! difference.

use std::collections::HashSet;

use af_core::{display, Action, ApprovalRequest};

/// Version of the fingerprint format.
///
/// The version is part of every fingerprint. A change of the rules below
/// therefore never matches an old entry.
const FORMAT: &str = "v1";

/// Largest length of a fingerprint, in characters.
const MAX_LENGTH: usize = 600;

/// Directories that hold files with a name that changes at every run.
const TEMPORARY_DIRECTORIES: [&str; 3] = ["/tmp/", "/var/tmp/", "/dev/shm/"];

/// Smallest run of digits that the fingerprint removes.
///
/// A time in seconds or milliseconds after the epoch has ten digits or more.
/// A port number and a normal count are shorter, so they stay.
const LONG_NUMBER: usize = 10;

/// Remembers the answers that hold for the whole session.
///
/// The memory holds a fingerprint of every action that the user allowed for
/// the session. The memory lives in the process of the firewall. It ends with
/// the session.
#[derive(Debug, Clone, Default)]
pub struct SessionMemory {
    /// Fingerprints of the actions that the user allowed for the session.
    allowed: HashSet<String>,
}

impl SessionMemory {
    /// Makes an empty memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes a stable fingerprint of a request.
    ///
    /// The fingerprint holds three parts: the identifier of the strongest
    /// rule, the name of the program, and the arguments of the action. The
    /// fingerprint holds no process identifier and no time, because those
    /// values change at every run and the memory then never matches.
    ///
    /// The function removes the parts of the arguments that change at every
    /// run:
    ///
    /// * the process identifier in a `/proc` path;
    /// * the file name below a temporary directory;
    /// * a run of ten digits or more.
    ///
    /// Everything else stays. `psql -c "DROP DATABASE a"` therefore gets a
    /// different fingerprint than `psql -c "DROP DATABASE b"`.
    pub fn fingerprint(req: &ApprovalRequest<'_>) -> String {
        let rule = req
            .verdict
            .top_match()
            .map(|matched| matched.rule_id.as_str())
            .unwrap_or("no-rule");
        let text = format!(
            "{FORMAT}|rule={rule}|kind={}|program={}|args={}",
            req.action.kind(),
            program_of(req),
            normalize(&arguments_of(req.action)),
        );
        display::sanitize(&display::truncate(&text, MAX_LENGTH))
    }

    /// Returns true when the user already allowed this kind of action.
    pub fn is_allowed(&self, req: &ApprovalRequest<'_>) -> bool {
        self.allowed.contains(&Self::fingerprint(req))
    }

    /// Remembers that the user allowed this kind of action.
    ///
    /// The memory holds every fingerprint one time only.
    pub fn allow(&mut self, req: &ApprovalRequest<'_>) {
        self.allowed.insert(Self::fingerprint(req));
    }

    /// Returns how many different actions the user allowed for the session.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Returns true when the user allowed no action for the session.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// Returns the name of the program of the request.
///
/// An exec action names the program that starts. Every other action uses the
/// program of the process that acts.
fn program_of(req: &ApprovalRequest<'_>) -> String {
    match req.action.program() {
        Some(program) => program.rsplit('/').next().unwrap_or(program).to_string(),
        None => req.process.program_name().to_string(),
    }
}

/// Returns the arguments of an action as one line of text.
///
/// The first word of a command line is the program itself. The fingerprint
/// already holds the program, so the function drops that word.
fn arguments_of(action: &Action) -> String {
    match action {
        Action::Exec { argv, .. } => argv
            .iter()
            .skip(1)
            .map(|word| word.as_str())
            .collect::<Vec<&str>>()
            .join(" "),
        Action::FileOpen { path, write } => {
            let mode = if *write { "write" } else { "read" };
            format!("{mode} {path}")
        }
        Action::NetworkConnect { host, addr, port } => {
            let host = host.as_deref().unwrap_or("-");
            format!("{host} {addr} {port}")
        }
        Action::Input { source, data } => format!("{source:?} {data}"),
    }
}

/// Removes the parts of the text that change at every run.
///
/// The function also makes the spaces equal, because a command line can hold
/// a line feed or two spaces between two words.
fn normalize(text: &str) -> String {
    text.split_whitespace()
        .map(normalize_word)
        .collect::<Vec<String>>()
        .join(" ")
}

/// Removes the parts of one word that change at every run.
fn normalize_word(word: &str) -> String {
    if let Some(masked) = mask_proc_path(word) {
        return masked;
    }
    if let Some(masked) = mask_temporary_file(word) {
        return masked;
    }
    mask_long_numbers(word)
}

/// Replaces the process identifier in a `/proc` path.
///
/// The path `/proc/1234/status` becomes `/proc/<pid>/status`.
fn mask_proc_path(word: &str) -> Option<String> {
    let rest = word.strip_prefix("/proc/")?;
    let mut parts = rest.splitn(2, '/');
    let head = parts.next().unwrap_or_default();
    if head.is_empty() || !head.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match parts.next() {
        Some(tail) => Some(format!("/proc/<pid>/{}", mask_long_numbers(tail))),
        None => Some("/proc/<pid>".to_string()),
    }
}

/// Replaces the name of a file below a temporary directory.
///
/// An agent often writes a script to `/tmp` with a new name at every run. The
/// path `/tmp/migrate-8842.sh` becomes `/tmp/<tmp>`. The directory stays, so
/// a file in the home directory keeps its name.
fn mask_temporary_file(word: &str) -> Option<String> {
    TEMPORARY_DIRECTORIES
        .iter()
        .find(|prefix| word.starts_with(**prefix))?;
    let (head, _name) = word.rsplit_once('/')?;
    Some(format!("{head}/<tmp>"))
}

/// Replaces every long run of digits with `<n>`.
///
/// A time and a random number are long. A port number and a small count are
/// short, so they stay.
fn mask_long_numbers(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut digits = String::new();
    for character in word.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        push_digits(&mut out, &mut digits);
        out.push(character);
    }
    push_digits(&mut out, &mut digits);
    out
}

/// Adds the collected digits to the result, masked when the run is long.
fn push_digits(out: &mut String, digits: &mut String) {
    if digits.is_empty() {
        return;
    }
    if digits.chars().count() >= LONG_NUMBER {
        out.push_str("<n>");
    } else {
        out.push_str(digits);
    }
    digits.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn a_new_memory_is_empty() {
        let memory = SessionMemory::new();
        assert!(memory.is_empty());
        assert_eq!(memory.len(), 0);
    }

    #[test]
    fn the_memory_allows_the_same_action_again() {
        let first = Fixture::psql("DROP DATABASE customer_prod");
        let mut memory = SessionMemory::new();
        memory.allow(&first.request());

        let again = Fixture::psql("DROP DATABASE customer_prod");
        assert!(memory.is_allowed(&again.request()));
        assert_eq!(memory.len(), 1);
    }

    #[test]
    fn the_memory_refuses_a_different_action() {
        let allowed = Fixture::psql("DROP DATABASE a");
        let mut memory = SessionMemory::new();
        memory.allow(&allowed.request());

        let other = Fixture::psql("DROP DATABASE b");
        assert!(!memory.is_allowed(&other.request()));
    }

    #[test]
    fn the_memory_refuses_a_different_rule() {
        let allowed = Fixture::psql("DROP DATABASE a");
        let mut memory = SessionMemory::new();
        memory.allow(&allowed.request());

        let mut other = Fixture::psql("DROP DATABASE a");
        other.verdict.matches[0].rule_id = "database.destructive.truncate".to_string();
        assert!(!memory.is_allowed(&other.request()));
    }

    #[test]
    fn the_memory_refuses_a_different_program() {
        let allowed = Fixture::psql("DROP DATABASE a");
        let mut memory = SessionMemory::new();
        memory.allow(&allowed.request());

        let mut other = Fixture::psql("DROP DATABASE a");
        other.set_program("mysql");
        assert!(!memory.is_allowed(&other.request()));
    }

    #[test]
    fn the_process_identifier_is_not_part_of_the_fingerprint() {
        let first = Fixture::psql("DROP DATABASE x");
        let mut second = Fixture::psql("DROP DATABASE x");
        second.process.pid = 999;
        second.process.start_ticks = 12345;
        second.ancestry[0].pid = 998;
        assert_eq!(
            SessionMemory::fingerprint(&first.request()),
            SessionMemory::fingerprint(&second.request())
        );
    }

    #[test]
    fn a_temporary_file_name_does_not_change_the_fingerprint() {
        let first = Fixture::exec("bash", &["/tmp/migrate-8842.sh"]);
        let second = Fixture::exec("bash", &["/tmp/migrate-1177.sh"]);
        assert_eq!(
            SessionMemory::fingerprint(&first.request()),
            SessionMemory::fingerprint(&second.request())
        );

        let elsewhere = Fixture::exec("bash", &["/home/dev/migrate-8842.sh"]);
        let other = Fixture::exec("bash", &["/home/dev/migrate-1177.sh"]);
        assert_ne!(
            SessionMemory::fingerprint(&elsewhere.request()),
            SessionMemory::fingerprint(&other.request())
        );
    }

    #[test]
    fn a_long_number_does_not_change_the_fingerprint() {
        let first = Fixture::exec("kubectl", &["logs", "--since-time=1724800000000"]);
        let second = Fixture::exec("kubectl", &["logs", "--since-time=1799911111111"]);
        assert_eq!(
            SessionMemory::fingerprint(&first.request()),
            SessionMemory::fingerprint(&second.request())
        );

        let port = Fixture::exec("psql", &["-p", "5432"]);
        let other_port = Fixture::exec("psql", &["-p", "5433"]);
        assert_ne!(
            SessionMemory::fingerprint(&port.request()),
            SessionMemory::fingerprint(&other_port.request())
        );
    }

    #[test]
    fn extra_spaces_do_not_change_the_fingerprint() {
        let first = Fixture::psql("DROP  DATABASE\tprod");
        let second = Fixture::psql("DROP DATABASE prod");
        assert_eq!(
            SessionMemory::fingerprint(&first.request()),
            SessionMemory::fingerprint(&second.request())
        );
    }

    #[test]
    fn a_proc_path_loses_the_process_identifier() {
        assert_eq!(
            mask_proc_path("/proc/1234/status").unwrap(),
            "/proc/<pid>/status"
        );
        assert_eq!(mask_proc_path("/proc/77").unwrap(), "/proc/<pid>");
        assert!(mask_proc_path("/proc/self/status").is_none());
    }

    #[test]
    fn the_fingerprint_holds_no_control_characters() {
        let hostile = Fixture::psql("DROP DATABASE prod\u{1b}[2J");
        let text = SessionMemory::fingerprint(&hostile.request());
        assert!(!text.contains('\u{1b}'), "fingerprint: {text}");
    }

    #[test]
    fn a_file_action_and_a_network_action_get_a_fingerprint() {
        let file = Fixture::file_open("/home/dev/.ssh/id_ed25519", true);
        let network = Fixture::network("prod.example.com", "10.0.0.7", 5432);
        let mut memory = SessionMemory::new();
        memory.allow(&file.request());
        memory.allow(&network.request());
        assert_eq!(memory.len(), 2);
        assert!(memory.is_allowed(&file.request()));
        assert!(memory.is_allowed(&network.request()));

        let other_file = Fixture::file_open("/home/dev/.ssh/config", true);
        assert!(!memory.is_allowed(&other_file.request()));
    }
}
