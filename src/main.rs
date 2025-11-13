mod cache;
mod cli;
mod config;
mod errors;
mod linter;
mod policy;
mod reporting;
mod rules;
mod sbom;
mod scanner;
mod secrets;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    cli.execute()
}
