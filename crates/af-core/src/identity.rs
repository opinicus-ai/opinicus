//! Detection of AI coding agents: signals in, confidence out.
//!
//! The direction of record asks for an extensible detection subsystem and not
//! for a list of executable names ([DIRECTION.md §5]). A new agent is a new
//! entry in the shared table, or a new [`Detector`], and not a redesign of
//! the core.
//!
//! The contract of every detector:
//!
//! * It reads only the facts of the [`DetectionInput`]. It never reads the
//!   operating system, so the same input always gives the same answer.
//! * It reports signals with a confidence weight. It never decides. The
//!   [`DetectorRegistry`] combines the weights and the caller decides what a
//!   combined confidence above [`TAG_THRESHOLD`] means.
//! * It reports, and the report is evidence. Nothing here is an enforcement
//!   boundary, and no rule may **allow** an action because a detector spoke.
//!
//! Precision comes first. A false agent tag is worse than no tag
//! ([MILESTONES.md §M3]), because everything downstream keys on the identity.
//! The tables below are therefore deliberately small, and every entry names a
//! marker that belongs to the agent alone. A generic marker that a human
//! toolchain also sets — an API key in the environment, a manifest that a
//! normal project can depend on — never reaches a tagging weight on its own.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Pid;

/// Confidence at which the registry tags a process as an agent.
///
/// One strong signal (a known executable, an agent package on the command
/// line) crosses the line alone. Weak signals must combine across detectors
/// to cross it, and the weakest signal of all — a dependency manifest —
/// cannot cross it with any partner below 0.66. The corpus of
/// `crates/af-core/tests/identity_corpus.rs` measures what the line costs in
/// recall and what it buys in precision.
pub const TAG_THRESHOLD: f32 = 0.75;

/// One known coding agent, and the markers that identify it.
struct KnownAgent {
    /// Short name of the agent, used as the tag. Example: `claude-code`.
    name: &'static str,
    /// Program names of the agent's own executables.
    executables: &'static [&'static str],
    /// Weight of an executable-name hit for this agent.
    ///
    /// Most names belong to the agent alone and carry the full weight. A name
    /// that other software also uses carries a supporting weight, so the name
    /// alone never tags the process.
    executable_confidence: f32,
    /// Package names that install the agent.
    packages: &'static [&'static str],
    /// Fragments of known install layouts, matched against the executable
    /// path and the command line.
    layouts: &'static [&'static str],
    /// Characteristic environment variables.
    ///
    /// The entry holds the variable name and the one value that makes the
    /// variable a marker of the agent itself. A value of `None` means the
    /// presence of the name already marks the agent.
    env: &'static [(&'static str, Option<&'static str>)],
}

/// The agents the built-in detectors know.
///
/// Every entry names a marker that belongs to the agent alone. Additions need
/// evidence, in the style of `research/detection/`, and a fixture in the
/// corpus of `crates/af-core/tests/identity_corpus.rs`.
const AGENTS: &[KnownAgent] = &[
    KnownAgent {
        name: "claude-code",
        executables: &["claude", "claude-code"],
        executable_confidence: 0.95,
        packages: &["@anthropic-ai/claude-code"],
        layouts: &[
            "node_modules/@anthropic-ai/claude-code",
            ".claude/local/claude",
        ],
        env: &[("CLAUDECODE", Some("1")), ("CLAUDE_CODE_ENTRYPOINT", None)],
    },
    KnownAgent {
        name: "codex",
        executables: &["codex"],
        executable_confidence: 0.95,
        packages: &["@openai/codex"],
        layouts: &["node_modules/@openai/codex"],
        env: &[],
    },
    KnownAgent {
        name: "opencode",
        executables: &["opencode"],
        executable_confidence: 0.95,
        packages: &["opencode-ai", "opencode-ai/opencode"],
        layouts: &["node_modules/opencode-ai/", ".opencode/bin/"],
        env: &[],
    },
    KnownAgent {
        name: "gemini-cli",
        executables: &["gemini", "gemini-cli"],
        executable_confidence: 0.9,
        packages: &["@google/gemini-cli"],
        layouts: &["node_modules/@google/gemini-cli"],
        env: &[],
    },
    KnownAgent {
        name: "copilot-cli",
        executables: &["copilot"],
        executable_confidence: 0.9,
        packages: &["@github/copilot"],
        layouts: &[],
        env: &[],
    },
    KnownAgent {
        name: "aider",
        executables: &["aider"],
        executable_confidence: 0.95,
        packages: &["aider-chat", "aider-install"],
        layouts: &[],
        env: &[],
    },
    KnownAgent {
        name: "pi",
        executables: &["pi"],
        // The word `pi` names other programs too, so the executable name
        // alone carries a supporting weight only.
        executable_confidence: 0.6,
        packages: &[],
        layouts: &[],
        env: &[("PI_CODING_AGENT", None)],
    },
];

/// Runners that fetch and run a package, and interpreters that run a script.
const RUNNERS: &[&str] = &["npx", "bunx", "uvx"];
/// Words after the program name that make `pnpm dlx ...` and `uv tool run ...`
/// into a runner command.
const RUNNER_WORDS: &[&[&str]] = &[&["dlx"], &["tool", "run"]];
const INTERPRETERS: &[&str] = &[
    "node", "bun", "deno", "tsx", "ts-node", "python", "python3", "pipx run",
];

/// The facts a detector may read.
///
/// The caller gathers the facts and the detector examines them. The split
/// keeps every detector pure: the same input always gives the same signals,
/// and a recorded assessment replays without reading the machine again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionInput {
    /// Full path of the program, when the caller could resolve it.
    ///
    /// The path carries the installation metadata: an executable under
    /// `node_modules/@anthropic-ai/claude-code` names its package manager and
    /// its package, whatever the program name is.
    pub exe: Option<String>,
    /// Command line of the process, the program first.
    pub argv: Vec<String>,
    /// Working directory of the process.
    pub cwd: String,
    /// Environment of the process that launched the session.
    ///
    /// The caller passes its own environment, because the root process
    /// inherits it. A detector reads only the names of its table and records
    /// only what matched.
    pub env: BTreeMap<String, String>,
    /// Dependency names that the manifests of the working directory carry.
    ///
    /// The caller reads the manifests once, at session start, and puts the
    /// dependency names here. A manifest alone is weak evidence — a normal
    /// project can depend on an agent package — so it never tags on its own.
    pub manifest_dependencies: BTreeSet<String>,
}

impl DetectionInput {
    /// Returns the program name without directories.
    ///
    /// The value comes from the executable path when it is known, and from
    /// the first command-line word when it is not.
    pub fn program_name(&self) -> &str {
        if let Some(exe) = self.exe.as_deref() {
            if let Some(name) = exe.rsplit('/').next() {
                if !name.is_empty() {
                    return name;
                }
            }
        }
        self.argv
            .first()
            .map(|word| word.rsplit('/').next().unwrap_or(word.as_str()))
            .unwrap_or("")
    }

    /// Returns the command line as one line of text.
    pub fn command_line(&self) -> String {
        self.argv.join(" ")
    }
}

/// One finding of one detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionSignal {
    /// Name of the detector that found the marker.
    pub detector: String,
    /// Agent the marker names.
    pub agent: String,
    /// What the detector saw, in one short line.
    pub detail: String,
    /// Weight of the finding, between 0 and 1.
    pub confidence: f32,
}

/// Examines detection facts and reports the agent markers it finds.
///
/// A detector reports. It never decides, and it never reads the operating
/// system. The registry combines the reports.
pub trait Detector: Send + Sync {
    /// Name of the detector, for the trace and for tests.
    fn name(&self) -> &'static str;

    /// Returns every marker that this detector found in the input.
    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal>;
}

/// The agent identity of the session root, as the registry assessed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentifiedAgent {
    /// Name of the agent, for example `claude-code`.
    pub name: String,
    /// Combined confidence, between 0 and 1.
    pub confidence: f32,
    /// Every signal the detectors found, strongest first.
    pub signals: Vec<DetectionSignal>,
}

/// The answer of the registry to one input.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Assessment {
    /// Combined confidence, between 0 and 1.
    pub confidence: f32,
    /// Every signal the detectors found.
    pub signals: Vec<DetectionSignal>,
    /// The identified agent, when the combined confidence crossed
    /// [`TAG_THRESHOLD`].
    pub agent: Option<IdentifiedAgent>,
}

/// Runs every registered detector and combines the weights.
///
/// The combination is a noisy OR over the **detectors**, not over the single
/// signals: each detector contributes its strongest signal once, so a table
/// with many hits from one detector cannot inflate the confidence by itself.
/// Signals from different detectors combine, which is the direction's rule —
/// signals are combined rather than relied on singly ([DIRECTION.md §5]).
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Makes a registry with the built-in detectors of this module.
    pub fn with_builtin_detectors() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(KnownExecutables));
        registry.register(Box::new(ArgvPatterns));
        registry.register(Box::new(InstallLayout));
        registry.register(Box::new(DependencyManifests));
        registry.register(Box::new(CharacteristicEnv));
        registry
    }

    /// Makes an empty registry.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Adds a detector. A new agent can be a new detector.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Assesses one input.
    pub fn assess(&self, input: &DetectionInput) -> Assessment {
        let mut signals: Vec<DetectionSignal> = Vec::new();
        for detector in &self.detectors {
            signals.extend(detector.detect(input));
        }

        // Each detector contributes its strongest signal once.
        let mut combined = 1.0f32;
        for detector in &self.detectors {
            let strongest = signals
                .iter()
                .filter(|signal| signal.detector == detector.name())
                .map(|signal| signal.confidence)
                .fold(0.0f32, f32::max);
            combined *= 1.0 - strongest;
        }
        let confidence = 1.0 - combined;

        let agent = if confidence >= TAG_THRESHOLD {
            signals.sort_by(|left, right| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            // The strongest signal names the agent. Two detectors that name
            // two different agents cannot both be right, and the registry
            // does not guess: the strongest marker wins and every signal
            // stays in the record.
            signals.first().map(|strongest| IdentifiedAgent {
                name: strongest.agent.clone(),
                confidence,
                signals: signals.clone(),
            })
        } else {
            None
        };

        Assessment {
            confidence,
            signals,
            agent,
        }
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Names the agent executables that the input runs.
struct KnownExecutables;

impl Detector for KnownExecutables {
    fn name(&self) -> &'static str {
        "known_executables"
    }

    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal> {
        let program = input.program_name().to_string();
        let mut out = Vec::new();
        for agent in AGENTS {
            if agent.executables.contains(&program.as_str()) {
                out.push(DetectionSignal {
                    detector: self.name().to_string(),
                    agent: agent.name.to_string(),
                    detail: format!("the program name is `{program}`"),
                    confidence: agent.executable_confidence,
                });
            }
        }
        out
    }
}

/// Names the agent packages that the command line carries.
///
/// Agents arrive through runners (`npx`, `bunx`, `pnpm dlx`) and through
/// interpreters that run a script of an installed package. The command line
/// names the package in both shapes, whatever the program name is.
struct ArgvPatterns;

impl Detector for ArgvPatterns {
    fn name(&self) -> &'static str {
        "argv_patterns"
    }

    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal> {
        let program = input.program_name().to_string();
        let line = input.command_line();
        let mut out = Vec::new();

        // A runner that fetches and runs a package: `npx claude`,
        // `bunx @openai/codex`, `pnpm dlx @google/gemini-cli`.
        let rest: Vec<&str> = input.argv.iter().skip(1).map(|w| w.as_str()).collect();
        let runs_package = RUNNERS.contains(&program.as_str())
            || RUNNER_WORDS.iter().any(|words| rest.starts_with(words));
        if runs_package {
            for agent in AGENTS {
                let package = agent
                    .packages
                    .iter()
                    .copied()
                    .chain(agent.executables.iter().copied())
                    .find(|name| rest.contains(name));
                if let Some(package) = package {
                    out.push(DetectionSignal {
                        detector: self.name().to_string(),
                        agent: agent.name.to_string(),
                        detail: format!("`{program}` runs the package `{package}`"),
                        confidence: 0.9,
                    });
                }
            }
        }

        // An interpreter that runs an agent's script, or the agent as a
        // module: `node .../node_modules/@anthropic-ai/claude-code/cli.js`,
        // `python -m aider`.
        if INTERPRETERS.contains(&program.as_str()) {
            for agent in AGENTS {
                let layout = agent
                    .layouts
                    .iter()
                    .copied()
                    .chain(agent.packages.iter().copied())
                    .find(|fragment| line.contains(fragment));
                if let Some(fragment) = layout {
                    out.push(DetectionSignal {
                        detector: self.name().to_string(),
                        agent: agent.name.to_string(),
                        detail: format!("the command line carries the install path `{fragment}`"),
                        confidence: 0.9,
                    });
                }
                if let Some(module) = module_argument(&input.argv) {
                    if agent.executables.contains(&module) || agent.packages.contains(&module) {
                        out.push(DetectionSignal {
                            detector: self.name().to_string(),
                            agent: agent.name.to_string(),
                            detail: format!("`{program}` runs the module `{module}`"),
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        out
    }
}

/// Returns the module name that an interpreter runs after `-m`.
fn module_argument(argv: &[String]) -> Option<&str> {
    let mut words = argv.iter().map(|word| word.as_str());
    while let Some(word) = words.next() {
        if word == "-m" || word == "--module" {
            return words.next();
        }
    }
    None
}

/// Names the agent install layouts that the executable path carries.
///
/// This is the package-manager installation metadata: where a package manager
/// put the agent, read from the resolved path of the program. The path
/// `~/.nvm/versions/node/v22/lib/node_modules/@anthropic-ai/claude-code/cli.js`
/// names npm, the scope and the package.
struct InstallLayout;

impl Detector for InstallLayout {
    fn name(&self) -> &'static str {
        "install_layout"
    }

    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal> {
        let Some(exe) = input.exe.as_deref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for agent in AGENTS {
            if let Some(fragment) = agent
                .layouts
                .iter()
                .copied()
                .chain(agent.packages.iter().copied())
                .find(|fragment| exe.contains(fragment))
            {
                out.push(DetectionSignal {
                    detector: self.name().to_string(),
                    agent: agent.name.to_string(),
                    detail: format!("the executable sits under `{fragment}`"),
                    confidence: 0.85,
                });
            }
        }
        out
    }
}

/// Names the agent packages that the dependency manifests of the working
/// directory carry.
///
/// A manifest is weak evidence by design: a project that develops **with** an
/// agent depends on its package, and `npm test` in that project is a normal
/// dev session, not an agent. The weight is therefore a supporting one, and
/// no partner below 0.66 can push it over the tagging line.
struct DependencyManifests;

impl Detector for DependencyManifests {
    fn name(&self) -> &'static str {
        "dependency_manifests"
    }

    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal> {
        let mut out = Vec::new();
        for agent in AGENTS {
            if let Some(package) = agent
                .packages
                .iter()
                .copied()
                .find(|package| input.manifest_dependencies.contains(*package))
            {
                out.push(DetectionSignal {
                    detector: self.name().to_string(),
                    agent: agent.name.to_string(),
                    detail: format!("a manifest of the working directory names `{package}`"),
                    confidence: 0.35,
                });
            }
        }
        out
    }
}

/// Names the environment markers that only the agent itself sets.
///
/// The table is deliberately tiny. An environment is the loudest place for
/// false positives — a human shell exports keys and flags of its own — so a
/// variable enters the table only when the agent sets it into the environment
/// of its own children, and an API key never enters it. `CLAUDECODE=1` is the
/// marker Claude Code puts into every process it starts; a value of `0`, or
/// any other value, is not a marker.
struct CharacteristicEnv;

impl Detector for CharacteristicEnv {
    fn name(&self) -> &'static str {
        "characteristic_env"
    }

    fn detect(&self, input: &DetectionInput) -> Vec<DetectionSignal> {
        let mut out = Vec::new();
        for agent in AGENTS {
            for (name, exact) in agent.env {
                let Some(value) = input.env.get(*name) else {
                    continue;
                };
                let marker = match exact {
                    Some(wanted) => *value == *wanted,
                    None => true,
                };
                if !marker {
                    continue;
                }
                out.push(DetectionSignal {
                    detector: self.name().to_string(),
                    agent: agent.name.to_string(),
                    detail: match exact {
                        Some(wanted) => format!("the environment carries `{name}={wanted}`"),
                        None => format!("the environment carries `{name}`"),
                    },
                    confidence: if exact.is_some() { 0.9 } else { 0.7 },
                });
            }
        }
        out
    }
}

/// Whether a process still links to the identified agent root of its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLink {
    /// The provenance graph links the process to the session root.
    Linked,
    /// The graph flagged the process as detached from the tree of the session
    /// root. See [`UnlinkReason`].
    Unlinked,
}

impl AgentLink {
    /// Returns a short label for logs and the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            AgentLink::Linked => "linked",
            AgentLink::Unlinked => "unlinked",
        }
    }
}

/// The agent identity that one event carries.
///
/// The tag travels with every event of a session whose root the detectors
/// identified. The identity propagates through the provenance graph: a
/// descendant of the tagged root is agent-controlled, and an unlinked
/// descendant keeps the tag — it is **unlinked, never foreign**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTag {
    /// Name of the identified agent.
    pub name: String,
    /// Combined confidence of the detection.
    pub confidence: f32,
    /// Whether the process that produced the event still links to the
    /// identified root.
    pub link: AgentLink,
}

/// The fact that a process sits in another session of the operating system
/// than the session root.
///
/// This is the B.6 liveness fact of [DETECTION-REQUIREMENTS.md]. A process
/// with this flag called `setsid`, or a process above it did, so it can
/// outlive the session and its later actions can arrive with no link back.
/// The flag never says that the process is foreign. The process keeps its
/// recorded ancestry and its agent identity — unlinked, never foreign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetach {
    /// Session identifier of the process.
    pub sid: Pid,
    /// Session identifier of the session root.
    pub root_sid: Pid,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Makes an input from a command line, with nothing else known.
    fn run(argv: &[&str]) -> DetectionInput {
        DetectionInput {
            argv: argv.iter().map(|word| word.to_string()).collect(),
            ..Default::default()
        }
    }

    /// Makes an input that carries environment variables.
    fn with_env(mut input: DetectionInput, vars: &[(&str, &str)]) -> DetectionInput {
        for (name, value) in vars {
            input.env.insert((*name).to_string(), (*value).to_string());
        }
        input
    }

    #[test]
    fn a_known_executable_tags_alone() {
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&run(&["claude"]));
        let agent = assessment.agent.expect("claude must tag");
        assert_eq!(agent.name, "claude-code");
        assert!(agent.confidence >= TAG_THRESHOLD);
    }

    #[test]
    fn a_runner_that_names_an_agent_package_tags() {
        let assessment =
            DetectorRegistry::with_builtin_detectors().assess(&run(&["npx", "@openai/codex"]));
        assert_eq!(assessment.agent.expect("npx codex must tag").name, "codex");
    }

    #[test]
    fn an_interpreter_that_runs_an_agent_script_tags() {
        let mut input = run(&[
            "node",
            "/home/dev/.nvm/versions/node/v22/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        ]);
        input.exe = Some("/usr/bin/node".to_string());
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert_eq!(
            assessment
                .agent
                .expect("node with the cli.js must tag")
                .name,
            "claude-code"
        );
    }

    #[test]
    fn an_install_layout_tags_through_the_executable_path() {
        let mut input = run(&["node", "cli.js"]);
        input.exe = Some("/home/dev/.opencode/bin/opencode".to_string());
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert_eq!(
            assessment
                .agent
                .expect("the opencode install path must tag")
                .name,
            "opencode"
        );
    }

    #[test]
    fn the_agent_marker_environment_tags_a_plain_shell() {
        // A shell that Claude Code started carries the marker. The process is
        // agent-controlled, and the detection sees it without a name.
        let input = with_env(run(&["bash", "corpus.sh"]), &[("CLAUDECODE", "1")]);
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert_eq!(
            assessment
                .agent
                .expect("a child of Claude Code must tag")
                .name,
            "claude-code"
        );
    }

    #[test]
    fn a_marker_at_the_wrong_value_stays_quiet() {
        let input = with_env(run(&["bash"]), &[("CLAUDECODE", "0")]);
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert!(
            assessment.signals.is_empty(),
            "`CLAUDECODE=0` is not a marker of the agent"
        );
        assert!(assessment.agent.is_none());
    }

    #[test]
    fn an_api_key_is_not_an_agent_marker() {
        let input = with_env(
            run(&["bash", "-c", "curl https://api.anthropic.com/"]),
            &[("ANTHROPIC_API_KEY", "sk-ant-EXAMPLE")],
        );
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert!(assessment.agent.is_none());
    }

    #[test]
    fn a_dependency_manifest_alone_stays_below_the_line() {
        // A project that develops with an agent depends on its package. A
        // build in that project is a normal dev session.
        let mut input = run(&["npm", "test"]);
        input
            .manifest_dependencies
            .insert("@anthropic-ai/claude-code".to_string());
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert!(!assessment.signals.is_empty(), "the manifest is a signal");
        assert!(
            assessment.agent.is_none(),
            "a manifest alone must not tag: confidence was {}",
            assessment.confidence
        );
    }

    #[test]
    fn an_ambiguous_name_alone_stays_below_the_line() {
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&run(&["pi"]));
        assert!(!assessment.signals.is_empty());
        assert!(assessment.agent.is_none());
    }

    #[test]
    fn weak_signals_combine_across_detectors() {
        // The ambiguous name `pi` and its environment marker together are
        // more than either alone.
        let input = with_env(run(&["pi"]), &[("PI_CODING_AGENT", "pi")]);
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert_eq!(assessment.agent.expect("the signals combine").name, "pi");
    }

    #[test]
    fn a_path_that_mentions_an_agent_without_the_layout_stays_quiet() {
        let mut input = run(&["node", "scripts/claude.js"]);
        input.exe = Some("/usr/bin/node".to_string());
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert!(
            assessment.agent.is_none(),
            "a file named after an agent is not an install layout"
        );
    }

    #[test]
    fn one_detector_cannot_inflate_the_confidence_by_repetition() {
        // Every package of the table in one manifest is still one supporting
        // signal, because the registry combines detectors and not hits.
        let mut input = run(&["npm", "test"]);
        for agent in AGENTS {
            for package in agent.packages {
                input.manifest_dependencies.insert(package.to_string());
            }
        }
        let assessment = DetectorRegistry::with_builtin_detectors().assess(&input);
        assert!(assessment.confidence < TAG_THRESHOLD);
        assert!(assessment.agent.is_none());
    }
}
