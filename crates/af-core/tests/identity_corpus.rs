//! The fixture corpus of agent identity detection: measured precision and
//! recall (`[af-3]`, milestone M3).
//!
//! No real coding agent is installed on the measurement machine, and none may
//! be. Every case below is therefore a **synthetic fixture**: a
//! [`DetectionInput`] built from the command shape, the install layout and
//! the environment markers that the real agents produce, named after the
//! agent it stands for. The corpus is the honest evidence the milestone
//! allows, and it says so.
//!
//! Run it with the numbers:
//!
//! ```sh
//! cargo test -p af-core --test identity_corpus -- --nocapture
//! ```
//!
//! The gate of M3, measured here:
//!
//! * **Precision 1.0.** No non-agent case tags. A false agent tag is worse
//!   than no tag, so one miss fails the gate.
//! * **Recall.** The measured value prints with the summary. The one known
//!   miss is the bare, ambiguous program name `pi`, which alone carries a
//!   supporting weight only.

use af_core::{DetectionInput, DetectorRegistry, TAG_THRESHOLD};
use std::collections::{BTreeMap, BTreeSet};

/// One case of the corpus.
struct Case {
    /// Name of the case, shown in the report.
    name: &'static str,
    /// True when the case stands for an agent session.
    is_agent: bool,
    /// The detection facts of the case.
    input: DetectionInput,
}

/// Builds an input from a command line, with nothing else known.
fn command(argv: &[&str]) -> DetectionInput {
    DetectionInput {
        argv: argv.iter().map(|word| word.to_string()).collect(),
        ..Default::default()
    }
}

/// Builds an input that also carries an executable path.
fn installed(exe: &str, argv: &[&str]) -> DetectionInput {
    DetectionInput {
        exe: Some(exe.to_string()),
        argv: argv.iter().map(|word| word.to_string()).collect(),
        ..Default::default()
    }
}

/// Builds an input that also carries environment variables.
fn environ(input: DetectionInput, vars: &[(&str, &str)]) -> DetectionInput {
    let mut env = BTreeMap::new();
    for (name, value) in vars {
        env.insert((*name).to_string(), (*value).to_string());
    }
    DetectionInput { env, ..input }
}

/// Builds an input whose working directory carries a `package.json` with
/// these dependency names.
fn in_repo(mut input: DetectionInput, dependencies: &[&str]) -> DetectionInput {
    let mut manifest_dependencies = BTreeSet::new();
    for name in dependencies {
        manifest_dependencies.insert((*name).to_string());
    }
    input.manifest_dependencies = manifest_dependencies;
    input
}

/// Every fixture of the corpus.
///
/// The agent cases use the real shapes the agents arrive in: their own
/// executable, an npm/pnpm/uv runner, an interpreter that runs the installed
/// package, and the environment markers the agents put into their children.
/// The non-agent cases are a normal developer's day, including the two
/// hardest near-misses: a repository that **develops with** an agent, and an
/// API key in the environment.
fn corpus() -> Vec<Case> {
    let home = "/home/dev";
    let nvm = "{home}/.nvm/versions/node/v22.11.0/lib/node_modules";
    vec![
        // ---- agent sessions, by their own executable -----------------------
        Case {
            name: "claude, bare",
            is_agent: true,
            input: installed("/usr/local/bin/claude", &["claude"]),
        },
        Case {
            name: "claude --continue",
            is_agent: true,
            input: installed("/usr/local/bin/claude", &["claude", "--continue"]),
        },
        Case {
            name: "codex exec",
            is_agent: true,
            input: installed("/usr/local/bin/codex", &["codex", "exec", "fix the build"]),
        },
        Case {
            name: "opencode run",
            is_agent: true,
            input: installed("/usr/local/bin/opencode", &["opencode", "run"]),
        },
        Case {
            name: "gemini -p",
            is_agent: true,
            input: installed(
                "/usr/local/bin/gemini",
                &["gemini", "-p", "explain this repo"],
            ),
        },
        Case {
            name: "aider --model",
            is_agent: true,
            input: installed("/usr/local/bin/aider", &["aider", "--model", "sonnet"]),
        },
        // ---- agent sessions, through a runner ------------------------------
        Case {
            name: "npx claude",
            is_agent: true,
            input: command(&["npx", "claude"]),
        },
        Case {
            name: "npx @anthropic-ai/claude-code",
            is_agent: true,
            input: command(&["npx", "@anthropic-ai/claude-code"]),
        },
        Case {
            name: "bunx @openai/codex",
            is_agent: true,
            input: command(&["bunx", "@openai/codex"]),
        },
        Case {
            name: "pnpm dlx @google/gemini-cli",
            is_agent: true,
            input: command(&["pnpm", "dlx", "@google/gemini-cli"]),
        },
        Case {
            name: "uvx aider-chat",
            is_agent: true,
            input: command(&["uvx", "aider-chat"]),
        },
        // ---- agent sessions, through an interpreter ------------------------
        Case {
            name: "node runs the claude-code cli",
            is_agent: true,
            input: command(&["node", &format!("{nvm}/@anthropic-ai/claude-code/cli.js")]),
        },
        Case {
            name: "bun runs the codex cli from the global install",
            is_agent: true,
            input: command(&[
                "bun",
                &format!("{home}/.bun/install/global/node_modules/@openai/codex/bin/codex.js"),
            ]),
        },
        Case {
            name: "node runs the claude self-install",
            is_agent: true,
            input: command(&["node", &format!("{home}/.claude/local/claude")]),
        },
        Case {
            name: "tsx runs the gemini cli of the project",
            is_agent: true,
            input: command(&[
                "tsx",
                &format!("{home}/app/node_modules/@google/gemini-cli/dist/index.js"),
            ]),
        },
        Case {
            name: "deno runs the codex package",
            is_agent: true,
            input: command(&["deno", "run", "npm:@openai/codex"]),
        },
        Case {
            name: "python -m aider",
            is_agent: true,
            input: command(&["python", "-m", "aider"]),
        },
        // ---- agent sessions, by install layout -----------------------------
        Case {
            name: "the opencode binary from its own install directory",
            is_agent: true,
            input: installed(&format!("{home}/.opencode/bin/opencode"), &["opencode"]),
        },
        // ---- agent sessions, by environment marker -------------------------
        Case {
            name: "bash started by claude code (CLAUDECODE=1)",
            is_agent: true,
            input: environ(command(&["bash", "corpus.sh"]), &[("CLAUDECODE", "1")]),
        },
        Case {
            name: "sh -c under claude code (CLAUDECODE=1)",
            is_agent: true,
            input: environ(command(&["sh", "-c", "make -j8"]), &[("CLAUDECODE", "1")]),
        },
        Case {
            name: "cargo test under claude code (its two markers)",
            is_agent: true,
            input: environ(
                command(&["cargo", "test"]),
                &[("CLAUDECODE", "1"), ("CLAUDE_CODE_ENTRYPOINT", "cli")],
            ),
        },
        Case {
            name: "pi with its own harness marker",
            is_agent: true,
            input: environ(
                installed("/usr/local/bin/pi", &["pi"]),
                &[("PI_CODING_AGENT", "pi")],
            ),
        },
        // ---- the known miss -------------------------------------------------
        Case {
            name: "pi, bare and ambiguous",
            is_agent: true,
            input: installed("/usr/local/bin/pi", &["pi"]),
        },
        // ---- normal development sessions ------------------------------------
        Case {
            name: "bash",
            is_agent: false,
            input: command(&["bash"]),
        },
        Case {
            name: "bash corpus.sh",
            is_agent: false,
            input: command(&["bash", "corpus.sh"]),
        },
        Case {
            name: "zsh -c ls",
            is_agent: false,
            input: command(&["zsh", "-c", "ls"]),
        },
        Case {
            name: "git status",
            is_agent: false,
            input: command(&["git", "status"]),
        },
        Case {
            name: "git push origin main",
            is_agent: false,
            input: command(&["git", "push", "origin", "main"]),
        },
        Case {
            name: "cargo build --release",
            is_agent: false,
            input: command(&["cargo", "build", "--release"]),
        },
        Case {
            name: "cargo test",
            is_agent: false,
            input: command(&["cargo", "test"]),
        },
        Case {
            name: "npm test",
            is_agent: false,
            input: command(&["npm", "test"]),
        },
        Case {
            name: "npm run build",
            is_agent: false,
            input: command(&["npm", "run", "build"]),
        },
        Case {
            name: "npm start",
            is_agent: false,
            input: command(&["npm", "start"]),
        },
        Case {
            name: "pnpm install",
            is_agent: false,
            input: command(&["pnpm", "install"]),
        },
        Case {
            name: "yarn dev",
            is_agent: false,
            input: command(&["yarn", "dev"]),
        },
        Case {
            name: "node server.js",
            is_agent: false,
            input: command(&["node", "server.js"]),
        },
        Case {
            name: "node dist/app.js",
            is_agent: false,
            input: command(&["node", "dist/app.js"]),
        },
        Case {
            name: "python3 train.py",
            is_agent: false,
            input: command(&["python3", "train.py"]),
        },
        Case {
            name: "pytest -q",
            is_agent: false,
            input: command(&["pytest", "-q"]),
        },
        Case {
            name: "go test ./...",
            is_agent: false,
            input: command(&["go", "test", "./..."]),
        },
        Case {
            name: "make -j8",
            is_agent: false,
            input: command(&["make", "-j8"]),
        },
        Case {
            name: "gcc -c main.c",
            is_agent: false,
            input: command(&["gcc", "-c", "main.c"]),
        },
        Case {
            name: "kubectl get pods",
            is_agent: false,
            input: command(&["kubectl", "get", "pods"]),
        },
        Case {
            name: "docker build",
            is_agent: false,
            input: command(&["docker", "build", "-t", "app", "."]),
        },
        Case {
            name: "curl an api",
            is_agent: false,
            input: command(&["curl", "https://api.example.com/v1"]),
        },
        Case {
            name: "psql SELECT",
            is_agent: false,
            input: command(&["psql", "-c", "SELECT 1"]),
        },
        Case {
            name: "rg over the sources",
            is_agent: false,
            input: command(&["rg", "fn main", "src/"]),
        },
        Case {
            name: "find by name",
            is_agent: false,
            input: command(&["find", ".", "-name", "*.md"]),
        },
        // ---- the near misses -------------------------------------------------
        Case {
            name: "npm test in a repo that develops with claude code",
            is_agent: false,
            input: in_repo(
                command(&["npm", "test"]),
                &["@anthropic-ai/claude-code", "vitest"],
            ),
        },
        Case {
            name: "node scripts/claude.js, an unrelated file name",
            is_agent: false,
            input: command(&["node", "scripts/claude.js"]),
        },
        Case {
            name: "bash with an ANTHROPIC_API_KEY exported",
            is_agent: false,
            input: environ(
                command(&["bash", "-c", "echo hi"]),
                &[("ANTHROPIC_API_KEY", "sk-ant-EXAMPLE")],
            ),
        },
        Case {
            name: "bash with CLAUDECODE=0",
            is_agent: false,
            input: environ(command(&["bash"]), &[("CLAUDECODE", "0")]),
        },
        Case {
            name: "cargo build under the pi harness marker alone",
            is_agent: false,
            input: environ(command(&["cargo", "build"]), &[("PI_CODING_AGENT", "pi")]),
        },
    ]
}

/// Runs the corpus and returns (true positives, false positives,
/// false negatives).
fn measure() -> (usize, usize, usize) {
    let registry = DetectorRegistry::with_builtin_detectors();
    let (mut tp, mut fp, mut fn_) = (0, 0, 0);
    for case in corpus() {
        let assessment = registry.assess(&case.input);
        let tagged = assessment.agent.is_some();
        match (case.is_agent, tagged) {
            (true, true) => tp += 1,
            (false, true) => {
                fp += 1;
                eprintln!(
                    "false tag: {} tagged {:?} (confidence {:.2})",
                    case.name,
                    assessment.agent.map(|a| a.name),
                    assessment.confidence
                );
            }
            (true, false) => {
                fn_ += 1;
                eprintln!(
                    "miss: {} stayed below the line (confidence {:.2} < {TAG_THRESHOLD})",
                    case.name, assessment.confidence
                );
            }
            (false, false) => {}
        }
    }
    (tp, fp, fn_)
}

#[test]
fn the_corpus_measures_precision_one() {
    let (tp, fp, fn_) = measure();
    let precision = tp as f32 / (tp + fp) as f32;
    println!(
        "identity corpus: {} agent fixtures, {} non-agent fixtures",
        corpus().iter().filter(|c| c.is_agent).count(),
        corpus().iter().filter(|c| !c.is_agent).count(),
    );
    println!(
        "identity corpus: precision {:.3} ({tp} true, {fp} false), recall {:.3} ({fn_} missed)",
        precision,
        tp as f32 / (tp + fn_) as f32,
    );
    assert_eq!(fp, 0, "a false agent tag is worse than no tag");
}

#[test]
fn the_corpus_measures_recall_of_at_least_ninety_percent() {
    let (tp, _, fn_) = measure();
    let recall = tp as f32 / (tp + fn_) as f32;
    assert!(
        recall >= 0.9,
        "recall {recall:.3} fell below the measured line"
    );
}
