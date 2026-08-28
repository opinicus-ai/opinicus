//! The rule source format, version 1.
//!
//! Every structure here uses `deny_unknown_fields`. A typo in a rule file is
//! therefore a load error and never a silent hole in the protection.

use std::collections::BTreeMap;

use af_core::{Decision, RiskLevel};
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
    /// The tests that the rule declares.
    #[serde(default)]
    pub tests: Vec<TestSource>,
}

fn yes() -> bool {
    true
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
}
