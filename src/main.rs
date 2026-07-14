//! agentcage — per-command Landlock sandbox for AI coding agents.
//!
//! The binary is a thin wrapper around `cli::main_entry`, which returns a
//! process exit code. All user-facing errors are printed to stderr by the
//! CLI layer; nothing here should ever panic on user input.

mod audit;
mod cli;
mod engine;
mod pattern;
mod policy;
mod sandbox;
mod timefmt;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cli::main_entry(args));
}
