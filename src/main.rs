pub mod classifier;
pub mod cli;
pub mod configuration;
pub mod extractor;
pub mod utils;

use std::{
    fs::File,
    io::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use clap::Parser;
use indicatif::ParallelProgressIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use cli::Cli;
use extractor::extract_for_family;
use utils::get_sample_data;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let global_args = cli.command.get_global_args();

    // containers for positive and negative results
    let res = Arc::new(Mutex::new(Vec::new()));
    let err = Arc::new(Mutex::new(Vec::new()));

    let _ = &global_args
        .files
        .par_iter()
        .progress()
        .for_each(|filename| match get_sample_data(&cli, filename) {
            Err(e) => add_string_to_arc(&err, format!("Error opening file {filename:?}: '{e}'")),
            Ok(data) => match extract_for_family(&data, &global_args.family) {
                Ok(c) => match serde_json::to_string(&c) {
                    Ok(s) => res.lock().unwrap().push(s),
                    Err(e) => add_string_to_arc(
                        &err,
                        format!("Failed to serialize malware configuration: '{e}'"),
                    ),
                },
                Err(e) => add_string_to_arc(
                    &err,
                    format!("Failed to extract configuration from {filename:?}: '{e}'"),
                ),
            },
        });

    // print errors to stderr
    for e in err.lock().unwrap().iter() {
        eprintln!("{e}");
    }

    // print results to stdout or specified file
    if let Some(output_path) = &global_args.output {
        let mut file = File::create(output_path)?;
        write!(&mut file, "{}", res.lock().unwrap().join("\n"))?;
    } else {
        println!("{}", res.lock().unwrap().join("\n"));
    }

    Ok(())
}

fn add_string_to_arc(arc: &Arc<Mutex<Vec<String>>>, string: String) {
    arc.lock().unwrap().push(string);
}
