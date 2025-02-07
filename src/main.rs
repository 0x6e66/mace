pub mod classifier;
pub mod cli;
pub mod extractor;

use anyhow::Result;
use clap::Parser;

use classifier::handle_sample;
use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();

    handle_sample(&cli)?;

    Ok(())
}
