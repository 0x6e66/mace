pub mod classifier;
pub mod cli;
pub mod configuration;
pub mod extractor;
pub mod utils;

use std::{fs::File, io::Write};

use anyhow::Result;
use clap::Parser;

use cli::Cli;
use extractor::extract_for_family;
use utils::get_sample_data;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let global_args = cli.command.get_global_args();

    let mut res = vec![];

    for filename in tqdm::tqdm(&global_args.files) {
        match get_sample_data(&cli, &filename) {
            Err(e) => {
                eprintln!("Error opening file {filename:?}: '{e}'");
            }
            Ok(data) => match extract_for_family(&data, &global_args.family) {
                Ok(c) => match serde_json::to_string(&c) {
                    Ok(s) => res.push(s),
                    Err(e) => eprintln!("Failed to serialize malware configuration: '{e}'"),
                },
                Err(e) => eprintln!("Failed to extract configuration from {filename:?}: '{e}'"),
            },
        }
    }

    if let Some(output_path) = &global_args.output {
        let mut file = File::create(output_path)?;
        write!(&mut file, "{}", res.join("\n"))?;
    } else {
        println!("{}", res.join("\n"));
    }
    Ok(())
}
