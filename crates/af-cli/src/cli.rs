//! Command-line interface definitions.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// A behaviour firewall for coding agents.
///
/// The firewall launches a program, follows every child process, and stops a
/// dangerous action before it completes.
#[derive(Debug, Parser)]
#[command(name = "agent-firewall", version, about, long_about = None)]
pub struct Cli {
    /// The sub-command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The sub-commands of the firewall.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launches a program and watches its whole process tree.
    Run(RunArgs),
    /// Evaluates a recorded trace again with the current rules.
    Replay(ReplayArgs),
    /// Draws the process tree of a recorded trace.
    Tree(TreeArgs),
    /// Works with policy files.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Reports what the monitor can observe on this machine.
    Doctor,
}

/// Options that select the rules.
#[derive(Debug, Clone, clap::Args)]
pub struct PolicyOptions {
    /// Adds a policy file or a directory of policy files. You can repeat it.
    #[arg(long = "policy", value_name = "PATH")]
    pub policy: Vec<PathBuf>,

    /// Does not load the rule pack inside the binary.
    #[arg(long = "no-builtin-policies")]
    pub no_builtin: bool,
}

/// Arguments of the `run` sub-command.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub policy: PolicyOptions,

    /// Writes the normalized events to this file as JSON Lines.
    #[arg(long, value_name = "PATH")]
    pub trace: Option<PathBuf>,

    /// Selects how much the trace keeps: all, balanced or evidence.
    #[arg(long, value_name = "MODE", default_value = "balanced")]
    pub retention: String,

    /// Selects how the firewall answers a question: ask, allow or deny.
    #[arg(long, value_name = "MODE")]
    pub approve: Option<String>,

    /// Denies when nobody answers in this many seconds.
    #[arg(long, value_name = "SECONDS")]
    pub approval_timeout: Option<u64>,

    /// Prints the process tree when the session ends.
    #[arg(long)]
    pub print_tree: bool,

    /// Prints every event as JSON on standard output.
    #[arg(long)]
    pub json: bool,

    /// Prints every normalized event as text.
    #[arg(short, long)]
    pub verbose: bool,

    /// Runs the program in this directory.
    #[arg(long, value_name = "PATH")]
    pub cwd: Option<PathBuf>,

    /// Does not read the standard input or the script of a new program.
    #[arg(long)]
    pub no_input_capture: bool,

    /// The program to run, after `--`.
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Arguments of the `replay` sub-command.
#[derive(Debug, clap::Args)]
pub struct ReplayArgs {
    /// The trace file to read.
    #[arg(value_name = "TRACE")]
    pub trace: PathBuf,

    #[command(flatten)]
    pub policy: PolicyOptions,

    /// Prints every evaluated action, and not only the actions that matched.
    #[arg(short, long)]
    pub verbose: bool,

    /// Prints the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments of the `tree` sub-command.
#[derive(Debug, clap::Args)]
pub struct TreeArgs {
    /// The trace file to read.
    #[arg(value_name = "TRACE")]
    pub trace: PathBuf,
}

/// The sub-commands of `policy`.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Lists every loaded rule.
    List {
        #[command(flatten)]
        policy: PolicyOptions,
        /// Prints the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validates policy files.
    Check {
        /// The files or directories to validate.
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,
    },
    /// Runs the tests inside the policy files.
    Test {
        #[command(flatten)]
        policy: PolicyOptions,
    },
}
