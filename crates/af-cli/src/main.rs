//! The command-line entry point of the Agent Firewall.

mod cli;
mod correlate_cmds;
mod inspect_cmds;
mod normalize;
mod policy_cmds;
mod report_cmds;
mod run;
mod summary;
mod telemetry_cmds;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run::run(args),
        Command::Replay(args) => inspect_cmds::replay(args),
        Command::Tree(args) => inspect_cmds::tree(args),
        Command::Correlate(args) => correlate_cmds::correlate_cmd(args),
        Command::Policy(command) => policy_cmds::run(command),
        Command::Telemetry(command) => telemetry_cmds::dispatch(command),
        Command::Report(args) => report_cmds::report(args),
        Command::Doctor(args) => inspect_cmds::doctor(args),
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("agent-firewall: {error:#}");
            std::process::exit(run::EXIT_ERROR);
        }
    }
}
