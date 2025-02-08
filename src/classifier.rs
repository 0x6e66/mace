use std::io::Read;

use anyhow::{anyhow, Result};
use clap::ValueEnum;

use crate::cli::{Cli, Commands, DirectArgs, ZipArgs};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum MalwareFamiliy {
    Copper,
    Bumblebee,
}

pub fn handle_sample(cli: &Cli) -> Result<()> {
    // 1. read data from file
    // 2. force_family ?
    //   none => classify via yara rules
    // 3. use extractor

    let (file_data, args) = match &cli.command {
        Commands::Direct(args) => (get_file_data_direct(args)?, &args.global_args),
        Commands::Zip(args) => (get_file_data_zip(args)?, &args.global_args),
    };

    let family = match &args.force_family {
        Some(family) => family,
        None => &classify_sample(&file_data)?,
    };

    dbg!(file_data.len());

    Ok(())
}

fn classify_sample(data: &[u8]) -> Result<MalwareFamiliy> {
    Err(anyhow!("TODO"))
}

fn get_file_data_direct(args: &DirectArgs) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(&args.global_args.file)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn get_file_data_zip(args: &ZipArgs) -> Result<Vec<u8>> {
    let file = std::fs::File::open(&args.global_args.file)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut file = match &args.sample_name {
        Some(sample_name) => match &args.password {
            Some(pw) => archive.by_name_decrypt(sample_name, pw.as_bytes())?,
            None => archive.by_name(sample_name)?,
        },
        None => match &args.password {
            Some(pw) => archive.by_index_decrypt(0, pw.as_bytes())?,
            None => archive.by_index(0)?,
        },
    };

    let mut buff = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buff)?;
    Ok(buff)
}
