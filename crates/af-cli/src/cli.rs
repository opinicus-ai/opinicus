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
    /// Compares the sensor's record with the monitor's trace.
    Correlate(CorrelateArgs),
    /// Works with policy files.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Works with optional telemetry: consent, samples, inspection.
    #[command(subcommand)]
    Telemetry(TelemetryCommand),
    /// Reports what the monitor can observe on this machine.
    Doctor(DoctorArgs),
}

/// Arguments of the `doctor` sub-command.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Reports for this filter mode: write-only, all-opens or off.
    #[arg(long, value_name = "MODE", default_value = "write-only")]
    pub syscall_filter: String,
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
///
/// The exit-code contract of a session, printed by `run --help`. Every code
/// a session can return is named here; `run --summary` writes the same code
/// into the session summary.
const EXIT_CODES_HELP: &str = "\
Exit codes:
  0        The session ended, and the firewall stopped nothing.
  3        The firewall stopped an action (a rule denial, a refusal or a
           ruling) and the session did not run to its end.
  2        The firewall could not run the session at all (an unknown
           option, a policy that cannot load, a monitor failure).
  N        The program of the session exited with code N, when the session
           ran to its end (for example 7 after `exit 7`).
  128+N    The program of the session died of signal N.";

/// Arguments of the `run` sub-command.
#[derive(Debug, clap::Args)]
#[command(after_help = EXIT_CODES_HELP)]
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

    /// Runs a deterministic headless session, for a continuous-integration
    /// job: every decision a rule leaves to a person resolves to deny, and
    /// no terminal is opened and no prompt is written, also not when one
    /// is attached.
    ///
    /// This is the CI shape of `--approve deny`, as a flag of `run` and not
    /// a separate `guard` command: `run` already owns every part a CI guard
    /// needs — the trace, the telemetry, the tree, the summary — and a
    /// second entry point would fork that flag surface and drift. The
    /// flag exists so a job never depends on terminal state: it fixes the
    /// answer (deny) where `--approve` selects a mode, and the two cannot
    /// be combined, so a job's posture is one line that cannot be weakened
    /// by accident. The alpha disclosure stays: a CI guard is still alpha.
    /// Combine with `--summary` for the machine-readable session record.
    #[arg(long, conflicts_with = "approve")]
    pub ci: bool,

    /// Writes a machine-readable JSON summary of the session to this file
    /// after the session ended.
    ///
    /// The summary names every rule decision with its rule id, its
    /// evidence line and its provenance chain, counts the denied,
    /// reported and quarantined actions and the questions an interactive
    /// session would have asked, and carries the exit code. The decisions
    /// come from the session's own `policy_decision` events, so a replay
    /// of the trace finds them again.
    #[arg(long, value_name = "PATH")]
    pub summary: Option<PathBuf>,

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

    /// Selects what the firewall sees inside a running program:
    /// write-only, all-opens or off.
    ///
    /// `write-only` holds a file open that can change the file, and every
    /// outgoing connection. `all-opens` also holds an open that only reads,
    /// which wakes the rules about reading a credential file and costs more
    /// on a file-heavy job. `off` installs no kernel filter, so the firewall
    /// stops at a new program only.
    #[arg(long, value_name = "MODE", default_value = "write-only")]
    pub syscall_filter: String,

    /// Selects the kernel floor: on or off.
    ///
    /// `on` enacts a Landlock ruleset before the first program runs, which
    /// makes the "always no" rule classes of the built-in pack impossible in
    /// the kernel: a credential store cannot be opened, a system tree cannot
    /// be written, a raw disk cannot be reached, and no signal leaves the
    /// session. The questions those rules asked disappear, and a denial the
    /// kernel makes is explained. The floor cannot be relaxed for a running
    /// session; a session that must touch a path the floor denies needs
    /// `--landlock off`.
    #[arg(long, value_name = "MODE", default_value = "on")]
    pub landlock: String,

    /// The program to run, after `--`.
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Packages redacted samples of this session into the telemetry outbox
    /// at the end of the run.
    ///
    /// Telemetry is opt-in twice: this flag opts the session in, and the
    /// consent file must grant at least one scope, or no sample is written.
    /// Nothing is sent anywhere — the outbox is a local directory you
    /// inspect and empty yourself. Without this flag the session never
    /// reads the consent file at all.
    #[arg(long)]
    pub telemetry: bool,

    /// Reads the telemetry consent here instead of the default file.
    #[arg(long, value_name = "PATH")]
    pub telemetry_config: Option<PathBuf>,

    /// Writes the telemetry samples here instead of the default outbox.
    #[arg(long, value_name = "PATH")]
    pub telemetry_outbox: Option<PathBuf>,
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

/// Arguments of the `correlate` sub-command.
#[derive(Debug, clap::Args)]
pub struct CorrelateArgs {
    /// The trace file the monitor wrote (the observed view).
    #[arg(value_name = "TRACE")]
    pub trace: PathBuf,

    /// The trace file of the in-process sensor (the expected view).
    #[arg(long, value_name = "PATH")]
    pub sensor: PathBuf,

    /// The registration record that names the sensor instances.
    #[arg(long, value_name = "PATH")]
    pub reg: PathBuf,

    /// How long an instance that proved it talks may stay quiet before the
    /// engine asks the external view whether its process still lives.
    #[arg(long, value_name = "MILLIS", default_value = "3000")]
    pub stale_ms: u64,

    /// Also compares write-intent file opens, not only connections.
    ///
    /// Research telemetry: the benign corpus measured 30 such
    /// contradictions in one normal session — `mkstemp` and other
    /// glibc-internal opens, retried lock attempts, reflog re-opens never
    /// cross the interposed libc — so the product posture compares
    /// connections only. The flag keeps the write comparison measurable.
    #[arg(long)]
    pub compare_write_opens: bool,

    /// Writes the disagreements as a schema-valid trace.
    #[arg(long, value_name = "PATH")]
    pub emit: Option<PathBuf>,

    #[command(flatten)]
    pub policy: PolicyOptions,

    /// Prints the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// The sub-commands of `telemetry`.
#[derive(Debug, Subcommand)]
pub enum TelemetryCommand {
    /// Shows the consent state, the outbox and the disclosure.
    Status(TelemetryStatusArgs),
    /// Grants consent for one or more scopes. Telemetry is off until you do.
    ///
    /// Consent is granular: each scope says what a sample may carry. It is
    /// revocable at any time with `telemetry off`, and with telemetry off
    /// the product is complete.
    On(TelemetryOnArgs),
    /// Revokes consent, for one scope or for all of them.
    Off(TelemetryOffArgs),
    /// Builds redacted samples from a recorded trace into the outbox.
    ///
    /// A sample centers on an event that made the firewall ask, quarantine,
    /// refuse or sense an attack on its visibility, and carries a window of
    /// surrounding events. Nothing is sent anywhere: the outbox is a local
    /// directory that you inspect and empty yourself.
    Sample(TelemetrySampleArgs),
    /// Prints one or more sample files, with a summary line.
    Inspect(TelemetryInspectArgs),
    /// Deletes samples: the named files, or the whole outbox with `--all`.
    Destroy(TelemetryDestroyArgs),
}

/// Arguments of `telemetry status`.
#[derive(Debug, clap::Args)]
pub struct TelemetryStatusArgs {
    /// Reads the consent here instead of the default file
    /// (`$XDG_CONFIG_HOME/agent-firewall/telemetry.json`).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Names this outbox instead of the default one
    /// (`$XDG_DATA_HOME/agent-firewall/outbox`).
    #[arg(long, value_name = "PATH")]
    pub outbox: Option<PathBuf>,
}

/// Arguments of `telemetry on`.
#[derive(Debug, clap::Args)]
pub struct TelemetryOnArgs {
    /// Grants this scope. Repeat it for more. `all` grants every scope.
    #[arg(long = "scope", value_name = "SCOPE", required = true)]
    pub scope: Vec<String>,

    /// Reads and writes the consent here instead of the default file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

/// Arguments of `telemetry off`.
#[derive(Debug, clap::Args)]
pub struct TelemetryOffArgs {
    /// Revokes this scope. Repeat it for more. No scope revokes everything.
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scope: Vec<String>,

    /// Reads and writes the consent here instead of the default file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

/// Arguments of `telemetry sample`.
#[derive(Debug, clap::Args)]
pub struct TelemetrySampleArgs {
    /// The trace file to read.
    #[arg(value_name = "TRACE")]
    pub trace: PathBuf,

    /// Reads the consent here instead of the default file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Writes the samples here instead of the default outbox.
    #[arg(long, value_name = "PATH")]
    pub outbox: Option<PathBuf>,
}

/// Arguments of `telemetry inspect`.
#[derive(Debug, clap::Args)]
pub struct TelemetryInspectArgs {
    /// The sample files to print.
    #[arg(value_name = "SAMPLE", required = true)]
    pub sample: Vec<PathBuf>,
}

/// Arguments of `telemetry destroy`.
#[derive(Debug, clap::Args)]
pub struct TelemetryDestroyArgs {
    /// The sample files to delete.
    #[arg(value_name = "SAMPLE")]
    pub sample: Vec<PathBuf>,

    /// Deletes every sample of the outbox instead of the named files.
    #[arg(long)]
    pub all: bool,

    /// Names this outbox instead of the default one.
    #[arg(long, value_name = "PATH")]
    pub outbox: Option<PathBuf>,
}

/// The sub-commands of `policy`.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Lists every loaded rule.
    List {
        #[command(flatten)]
        policy: PolicyOptions,
        /// Marks the rules for this filter mode: write-only, all-opens or off.
        #[arg(long, value_name = "MODE", default_value = "write-only")]
        syscall_filter: String,
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
