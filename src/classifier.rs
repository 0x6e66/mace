use std::{io::Read, path::PathBuf};

use anyhow::Result;
use clap::ValueEnum;

use crate::cli::{Cli, Mode};

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

    // 1.
    let file_data = match cli.mode {
        Mode::Direct => get_file_data_direct(cli)?,
        _ => get_file_data_zip(cli)?,
    };

    dbg!(file_data.len());

    Ok(())
}

fn get_file_data_direct(cli: &Cli) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(&cli.file)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn get_file_data_zip(cli: &Cli) -> Result<Vec<u8>> {
    let files = get_files_from_zip(&cli.file, cli.password.as_deref())?;

    // TODO: change this. also add functionality to specify one file in a zip (in case more than
    // one file is present)
    Ok(files[0].1.clone())
}

fn get_files_from_zip(
    filepath: &PathBuf,
    password: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let file = std::fs::File::open(filepath)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut res = vec![];

    for i in 0..archive.len() {
        let mut file = match password {
            None => archive.by_index(i)?,
            Some(pw) => archive.by_index_decrypt(i, pw.as_bytes())?,
        };
        let mut buff = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buff)?;
        let filename = file.name().to_owned();

        res.push((filename, buff));
    }

    Ok(res)
}
