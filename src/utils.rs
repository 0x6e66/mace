use std::{io::Read, path::Path};

use anyhow::Result;
use exe::{ImageSectionHeader, PE, VecPE};
use iced_x86::{Code, Decoder, DecoderOptions};

use crate::cli::{Cli, Commands};

pub fn get_sample_data(cli: &Cli, path: &Path) -> Result<Vec<u8>> {
    let file_data = match &cli.command {
        Commands::Direct(_) => get_file_data_direct(path)?,
        Commands::Zip(args) => get_file_data_zip(path, args.password.as_ref())?,
    };

    Ok(file_data)
}
fn get_file_data_direct(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn get_file_data_zip(path: &Path, password: Option<&String>) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut file = match password {
        Some(pw) => archive.by_index_decrypt(0, pw.as_bytes())?,
        None => archive.by_index(0)?,
    };

    let mut buff = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buff)?;
    Ok(buff)
}

pub fn get_section_data_by_name<'a>(pe: &'a VecPE, name: &str) -> Result<&'a [u8]> {
    let section_header = pe.get_section_by_name(name)?;

    let start = section_header.pointer_to_raw_data.0 as usize;
    let size = section_header.size_of_raw_data as usize;
    let end = start + size;

    Ok(&pe.get_buffer()[start..end])
}

pub fn get_section_data_by_header<'a>(
    pe: &'a VecPE,
    section_header: &ImageSectionHeader,
) -> &'a [u8] {
    let start = section_header.pointer_to_raw_data.0 as usize;
    let size = section_header.size_of_raw_data as usize;
    let end = start + size;

    &pe.get_buffer()[start..end]
}

/// Converts a virtual address inside the selected section to a raw address
pub fn virtual_to_raw_address(section_header: &ImageSectionHeader, addr: u32) -> u32 {
    let raw_addr_start = section_header.pointer_to_raw_data.0;
    let virt_addr_start = section_header.virtual_address.0;

    addr - virt_addr_start + raw_addr_start
}

/// Converts a raw address to a virtual address inside the selected section
pub fn raw_to_virtual_address(section_header: &ImageSectionHeader, addr: u32) -> u32 {
    let raw_addr_start = section_header.pointer_to_raw_data.0;
    let virt_addr_start = section_header.virtual_address.0;

    addr - virt_addr_start + raw_addr_start
}

/// Determines if the PE is 32 or 64-bit architecture
pub fn get_bitness_from_pe(pe: &VecPE) -> u32 {
    match pe.get_arch() {
        Ok(exe::Arch::X86) => 32,
        Ok(exe::Arch::X64) => 64,
        Err(_) => panic!("Cloud not determine architecture of provided PE file"),
    }
}

#[derive(Debug)]
pub struct Function {
    pub address: u32,
    pub data: Vec<u8>,
    pub function_calls: Vec<u32>,
}

/// Generates an overview of all the functions that are called in the text section
pub fn generate_function_overview(pe: &VecPE) -> Result<Vec<Function>> {
    let text_section_header = pe.get_section_by_name(".text")?;
    let text_section_data = get_section_data_by_header(pe, text_section_header);
    let bitness = get_bitness_from_pe(pe);

    let virt_addr_start = text_section_header.virtual_address.0 as usize;
    let raw_data_size = text_section_header.size_of_raw_data as usize;

    let initial_ip = virt_addr_start as u64;
    let decoder = Decoder::with_ip(bitness, text_section_data, initial_ip, DecoderOptions::NONE);

    let mut functions: Vec<Function> = Vec::new();

    for instruction in decoder
        .into_iter()
        .filter(|i| matches!(i.code(), Code::Call_rel32_32))
    {
        let func_addr = instruction.memory_displacement32();

        if func_addr as usize >= raw_data_size + virt_addr_start {
            continue;
        }

        if !functions
            .iter()
            .any(|Function { address, .. }| *address == func_addr)
        {
            let func_start = func_addr as usize - virt_addr_start;
            let (size, function_calls) = get_size_and_function_calls_of_function(
                text_section_header,
                bitness,
                func_addr,
                &text_section_data[func_start..],
            );
            functions.push(Function {
                address: func_addr,
                data: text_section_data[func_start..func_start + size].to_vec(),
                function_calls,
            });
        }
    }

    Ok(functions)
}

/// Gets the size and function calls of a function by iterating over the function and looking for a `ret` instruction
pub fn get_size_and_function_calls_of_function(
    text_section_header: &ImageSectionHeader,
    bitness: u32,
    ip_of_function: u32,
    start_of_function_data: &[u8],
) -> (usize, Vec<u32>) {
    let virt_addr_start = text_section_header.virtual_address.0 as usize;
    let raw_data_size = text_section_header.size_of_raw_data as usize;
    let mut decoder = Decoder::with_ip(
        bitness,
        start_of_function_data,
        ip_of_function.into(),
        DecoderOptions::NONE,
    );

    let mut size = 0;
    let mut function_calls = vec![];

    if decoder.can_decode() {
        let instruction = decoder.decode();
        size += instruction.len();

        match instruction.code() {
            Code::Jmp_rm16 | Code::Jmp_rm32 | Code::Jmp_rm64 => return (size, function_calls),
            _ => (),
        }
    }

    for instruction in decoder {
        size += instruction.len();
        match instruction.code() {
            Code::Retnw | Code::Retnd | Code::Retnq => break,
            Code::Call_rel32_32 => {
                let func_addr = instruction.memory_displacement32();
                if (func_addr as usize) < raw_data_size + virt_addr_start
                    && !function_calls.iter().any(|f| *f == func_addr)
                {
                    function_calls.push(func_addr);
                }
            }
            _ => (),
        }
    }

    (size, function_calls)
}
