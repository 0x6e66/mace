pub mod classifier;
pub mod cli;
pub mod extractor;
pub mod utils;

use anyhow::Result;
use clap::Parser;

use classifier::classify_sample;
use cli::Cli;
use extractor::extract_for_families;
use utils::get_sample_data;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let sample_data = get_sample_data(&cli)?;
    let global_args = cli.command.get_global_args();

    let families = match global_args.force_family {
        Some(family) => vec![family],
        None => classify_sample(&sample_data)?,
    };

    extract_for_families(&sample_data, &families);

    Ok(())
}
