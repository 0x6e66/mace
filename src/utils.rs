use std::io::Read;

use anyhow::Result;
use exe::{ImageSectionHeader, VecPE, PE};

use crate::cli::{Cli, Commands, DirectArgs, ZipArgs};

pub fn get_sample_data(cli: &Cli) -> Result<Vec<u8>> {
    let file_data = match &cli.command {
        Commands::Direct(args) => get_file_data_direct(args)?,
        Commands::Zip(args) => get_file_data_zip(args)?,
    };

    Ok(file_data)
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

pub fn ghidra_addr_to_slice_index(section_header: &ImageSectionHeader, addr: usize) -> usize {
    let raw_addr_start = section_header.pointer_to_raw_data.0 as usize;
    let virt_addr_start = section_header.virtual_address.0 as usize;

    raw_addr_start + addr - virt_addr_start
}

pub fn get_bitness_from_pe(pe: &VecPE) -> Option<u32> {
    match pe.get_valid_nt_headers() {
        Ok(exe::NTHeaders::NTHeaders32(_)) => Some(32),
        Ok(exe::NTHeaders::NTHeaders64(_)) => Some(64),
        Err(_) => None,
    }
}
