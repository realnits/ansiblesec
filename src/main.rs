mod cli;
mod config;
mod scanner;
mod rules;
mod reporting;
mod sbom;
mod errors;
mod cache;
mod secrets;
mod linter;
mod policy;

use anyhow::Result;
use cli::Cli;
use clap::Parser;

fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    cli.execute()
}
