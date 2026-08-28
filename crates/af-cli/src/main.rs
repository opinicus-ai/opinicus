//! The command-line entry point of the Agent Firewall.

mod cli;
mod inspect_cmds;
mod normalize;
mod policy_cmds;
mod run;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run::run(args),
        Command::Replay(args) => inspect_cmds::replay(args),
        Command::Tree(args) => inspect_cmds::tree(args),
        Command::Policy(command) => policy_cmds::run(command),
        Command::Doctor(args) => inspect_cmds::doctor(args),
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("agent-firewall: {error:#}");
            std::process::exit(2);
        }
    }
}
