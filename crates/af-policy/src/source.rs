//! The rule source format, version 1.
//!
//! Every structure here uses `deny_unknown_fields`. A typo in a rule file is
//! therefore a load error and never a silent hole in the protection.

use std::collections::BTreeMap;

use af_core::{Decision, MarkScope, RiskLevel};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

/// The only rule format version that this crate reads.
pub const FORMAT_VERSION: u32 = 1;

/// A list of words that a rule file may write as one word or as a list.
///
/// Both forms below mean the same thing:
///
/// ```yaml
/// program: psql
/// program: [psql, mysql]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Words(pub Vec<String>);

impl<'de> Deserialize<'de> for Words {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WordsVisitor;

        impl<'de> Visitor<'de> for WordsVisitor {
            type Value = Words;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a word or a list of words")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Words, E> {
                Ok(Words(vec![value.to_string()]))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Words, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<String>()? {
                    out.push(item);
                }
                Ok(Words(out))
            }
        }

        deserializer.deserialize_any(WordsVisitor)
    }
}

/// Which action kind a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// A process is about to run a program.
    Exec,
    /// A process opens a file.
    FileOpen,
    /// A process opens a network connection.
    NetworkConnect,
    /// Content that a process reads or receives.
    Input,
}

impl ActionKind {
    /// Returns the label that the rule file uses.
    pub fn label(&self) -> &'static str {
        match self {
            ActionKind::Exec => "exec",
            ActionKind::FileOpen => "file_open",
            ActionKind::NetworkConnect => "network_connect",
            ActionKind::Input => "input",
        }
    }
}

/// One rule file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Version of the rule format. Only `1` is valid.
    pub version: u32,
    /// Name of the pack, for example `builtin.database`.
    pub name: String,
    /// What the pack protects, in one line.
    #[serde(default)]
    pub description: String,
    /// The rules of the pack.
    #[serde(default)]
    pub rules: Vec<RuleSource>,
}

/// One rule, as the file writes it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSource {
    /// Stable identifier, for example `database.destructive.drop-database`.
    pub id: String,
    /// Short title for the user.
    pub title: String,
    /// Category, for example `database` or `git`.
    #[serde(default)]
    pub category: String,
    /// How dangerous the rule considers the action.
    pub risk: RiskLevel,
    /// What the rule wants the firewall to do.
    pub decision: Decision,
    /// Why the rule matched, in words the user can read.
    #[serde(default)]
    pub reason: String,
    /// Links that explain the danger.
    #[serde(default)]
    pub references: Vec<String>,
    /// False switches the rule off. The default is true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The condition of the rule.
    #[serde(rename = "match")]
    pub match_: MatchSource,
    /// Conditions that switch the rule off for one action.
    #[serde(default)]
    pub exceptions: Vec<MatchSource>,
    /// A fact that the session writes down when the condition matches.
    #[serde(default)]
    pub remember: Option<RememberSource>,
    /// A window and a count that the rule must reach before it fires.
    #[serde(default)]
    pub threshold: Option<ThresholdSource>,
    /// The tests that the rule declares.
    #[serde(default)]
    pub tests: Vec<TestSource>,
}

fn yes() -> bool {
    true
}

/// What the session writes down when a rule matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberSource {
    /// Name of the mark, for example `credential-read`.
    pub mark: String,
    /// How far the mark reaches. The default is the whole session.
    #[serde(default)]
    pub scope: MarkScope,
    /// How long the mark counts, in seconds. No value means the session.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// A window and a count that a rule must reach before it fires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdSource {
    /// Length of the trailing window, in seconds.
    pub window_seconds: u64,
    /// How many hits the window must hold, this action included.
    pub at_least: usize,
    /// What makes two hits different. The default counts every hit.
    #[serde(default)]
    pub distinct: DistinctKey,
}

/// What makes two hits of a rule different.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistinctKey {
    /// Count every hit, not the different values.
    #[default]
    None,
    /// The path of the file.
    Path,
    /// The host name or the address of the connection.
    Host,
    /// The program name.
    Program,
    /// The command line, joined with one space.
    ArgvJoined,
}

impl DistinctKey {
    /// Returns the label that the rule file uses.
    pub fn label(&self) -> &'static str {
        match self {
            DistinctKey::None => "none",
            DistinctKey::Path => "path",
            DistinctKey::Host => "host",
            DistinctKey::Program => "program",
            DistinctKey::ArgvJoined => "argv_joined",
        }
    }
}

/// A question about a mark that an earlier action wrote down.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkedSource {
    /// Name of the mark.
    pub mark: String,
    /// How old the mark may be, in seconds. No value means any age.
    #[serde(default)]
    pub within_seconds: Option<u64>,
    /// How far the reader looks. The default is the whole session.
    #[serde(default)]
    pub scope: MarkScope,
}

/// A question about a value that the session did not know at its start.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineMissingSource {
    /// Name of the baseline set, for example `git_remotes`.
    pub set: String,
    /// Pattern with exactly one group that reads the value from the arguments.
    pub capture: String,
}

/// A question about a variable token that the child shell expands.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VarResolvesSource {
    /// Pattern with exactly one group that reads the variable name from the
    /// command line, or from the input text of an input action.
    pub capture: String,
    /// Where the value may land for the condition to match.
    pub to: Vec<VarResolveTarget>,
}

/// Where the value of a variable may land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VarResolveTarget {
    /// The home directory of the child process.
    Home,
    /// The root of the file system, which an empty value also produces when
    /// the token carries a trailing slash.
    Root,
}

/// One condition.
///
/// Every field is optional. Every field that the file writes must match, so
/// the fields of one block are joined with AND.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSource {
    /// The action kind that the block applies to.
    #[serde(default)]
    pub action: Option<ActionKind>,
    /// Program names. One of them must be the program of the action.
    #[serde(default)]
    pub program: Option<Words>,
    /// Path patterns for the program file. One of them must match.
    #[serde(default)]
    pub exe_glob: Option<Words>,
    /// Exact arguments. Every one of them must be in the command line.
    #[serde(default)]
    pub argv_contains: Option<Words>,
    /// Exact arguments. One of them must be in the command line.
    #[serde(default)]
    pub argv_any: Option<Words>,
    /// Pattern for the command line, joined with a space.
    #[serde(default)]
    pub argv_matches: Option<String>,
    /// Pattern for the command line that must not match.
    #[serde(default)]
    pub argv_not_matches: Option<String>,
    /// Pattern for observed input, for example standard input or a script.
    #[serde(default)]
    pub input_matches: Option<String>,
    /// Path prefixes for the working directory. One of them must match.
    #[serde(default)]
    pub cwd_prefix: Option<Words>,
    /// Path prefixes for the working directory. None of them may match.
    #[serde(default)]
    pub cwd_not_prefix: Option<Words>,
    /// Exact file paths. One of them must match.
    #[serde(default)]
    pub path: Option<Words>,
    /// Path prefixes for the file. One of them must match.
    #[serde(default)]
    pub path_prefix: Option<Words>,
    /// Path patterns for the file. One of them must match.
    #[serde(default)]
    pub path_glob: Option<Words>,
    /// Pattern for the file path.
    #[serde(default)]
    pub path_matches: Option<String>,
    /// True selects a write, false selects a read.
    #[serde(default)]
    pub write: Option<bool>,
    /// Host names or addresses. One of them must match.
    #[serde(default)]
    pub host: Option<Words>,
    /// Pattern for the host name or the address.
    #[serde(default)]
    pub host_matches: Option<String>,
    /// The port of the connection.
    #[serde(default)]
    pub port: Option<u16>,
    /// Ports. One of them must be the port of the connection.
    #[serde(default)]
    pub port_in: Option<Vec<u16>>,
    /// Program names. The nearest parent must be one of them.
    #[serde(default)]
    pub parent_program: Option<Words>,
    /// Program names. One process of the ancestry must be one of them.
    #[serde(default)]
    pub ancestor_program: Option<Words>,
    /// How far the process must sit below the root of the session.
    #[serde(default)]
    pub ancestor_depth_at_least: Option<usize>,
    /// Environment names with a pattern for the value.
    ///
    /// An empty pattern means that only the name must be present.
    #[serde(default)]
    pub env: Option<BTreeMap<String, String>>,
    /// A condition that must not match.
    #[serde(default)]
    pub not: Option<Box<MatchSource>>,
    /// Conditions that must all match.
    #[serde(default)]
    pub all_of: Option<Vec<MatchSource>>,
    /// Conditions of which one must match.
    #[serde(default)]
    pub any_of: Option<Vec<MatchSource>>,
    /// A mark that an earlier action of the session wrote down.
    #[serde(default)]
    pub marked: Option<MarkedSource>,
    /// A value that the session did not know at its start.
    #[serde(default)]
    pub baseline_missing: Option<BaselineMissingSource>,
    /// A variable token that the child shell expands to a named target.
    #[serde(default)]
    pub var_resolves: Option<VarResolvesSource>,
}

/// One process record of a declared test.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestProcess {
    /// Process identifier. The default is `1`.
    #[serde(default)]
    pub pid: Option<i32>,
    /// Identifier of the parent process.
    #[serde(default)]
    pub ppid: Option<i32>,
    /// Full path of the program.
    #[serde(default)]
    pub exe: Option<String>,
    /// Program name without directories.
    #[serde(default)]
    pub comm: Option<String>,
    /// Command line of the process.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Working directory of the process.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Selected environment variables of the process.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// The file that a declared test opens.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestFileOpen {
    /// Path of the file.
    pub path: String,
    /// True when the process opens the file for writing.
    #[serde(default)]
    pub write: bool,
}

/// The connection that a declared test opens.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestConnect {
    /// Host name of the remote end.
    #[serde(default)]
    pub host: Option<String>,
    /// Address of the remote end.
    #[serde(default)]
    pub addr: Option<String>,
    /// Port of the remote end.
    pub port: u16,
}

/// The observed content of a declared test.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestInput {
    /// Where the content came from. The default is `stdin`.
    #[serde(default)]
    pub source: Option<TestInputSource>,
    /// The content itself.
    pub data: String,
}

/// Where the content of a declared test came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestInputSource {
    /// The command line of the process.
    Argv,
    /// The standard input stream of the process.
    Stdin,
    /// A file that the process reads.
    File,
    /// An environment variable.
    Environment,
}

/// One step that happened before the action of a test.
///
/// A step has the same shape as the action of a test. It builds the memory of
/// the session, and the test judges only the action that comes after it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestStep {
    /// Time of the step, in seconds after the start of the test.
    ///
    /// Without a value the steps stand one second apart, and the action of
    /// the test comes last.
    #[serde(default)]
    pub at_seconds: Option<u64>,
    /// The process that performs the step.
    #[serde(default)]
    pub process: TestProcess,
    /// Ancestry of the process, nearest parent first and session root last.
    #[serde(default)]
    pub ancestry: Vec<TestProcess>,
    /// A file open instead of the default program start.
    #[serde(default)]
    pub file_open: Option<TestFileOpen>,
    /// A network connection instead of the default program start.
    #[serde(default)]
    pub connect: Option<TestConnect>,
    /// Observed content instead of the default program start.
    #[serde(default)]
    pub input: Option<TestInput>,
    /// How many times the step repeats. The default is one.
    ///
    /// A repeated step stands one second after the one before it, so a test
    /// can write twenty deletes in one line.
    #[serde(default)]
    pub repeat: Option<usize>,
}

/// One test that a rule declares.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSource {
    /// What the test proves, in one line.
    pub name: String,
    /// The decision that the rule must give.
    pub expect: Decision,
    /// True when the rule must match, false when it must not match.
    ///
    /// The default is true for a test that expects a decision which stops
    /// the action, and false for a test that expects `allow`. A quiet rule
    /// therefore needs `expect_match: true` for a positive test.
    #[serde(default)]
    pub expect_match: Option<bool>,
    /// The process that performs the action.
    #[serde(default)]
    pub process: TestProcess,
    /// Ancestry of the process, nearest parent first and session root last.
    #[serde(default)]
    pub ancestry: Vec<TestProcess>,
    /// A file open instead of the default program start.
    #[serde(default)]
    pub file_open: Option<TestFileOpen>,
    /// A network connection instead of the default program start.
    #[serde(default)]
    pub connect: Option<TestConnect>,
    /// Observed content instead of the default program start.
    #[serde(default)]
    pub input: Option<TestInput>,
    /// The steps that happened before the action of the test.
    #[serde(default)]
    pub history: Vec<TestStep>,
    /// Time of the action, in seconds after the start of the test.
    ///
    /// Without a value the action comes one second after the last step.
    #[serde(default)]
    pub at_seconds: Option<u64>,
    /// The named sets that the launcher recorded at session start.
    #[serde(default)]
    pub baseline: BTreeMap<String, Vec<String>>,
}
