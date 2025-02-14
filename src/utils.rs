use std::{collections::HashMap, io::Read};

use anyhow::Result;
use exe::{ImageSectionHeader, PEType, VecPE, PE};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction};

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

pub fn get_bitness_from_pe(pe: &VecPE) -> u32 {
    match pe.get_arch() {
        Ok(exe::Arch::X86) => 32,
        Ok(exe::Arch::X64) => 64,
        Err(_) => panic!("Cloud not determine architecture of provided PE file"),
    }
}

/// Generates an overview of all the functions that are called in the text section
///
/// Return a Vec of tuples. Each tuple is structured as follows:
///     t.0 => **virtual** address of the function
///     t.1 => size of the function in bytes (distance from the beginning to the next `ret`, where
///     the `ret` in included in the length)
///
/// The following function would have the length 20:
///
/// ```asm
///         8b 4c 24 04     MOV        ECX,dword ptr [ESP + param_1]
///     LAB_0040279c
///         b8 18 00        MOV        EAX,0x18
///         00 00
///         39 c8           CMP        EAX,ECX
///         73 04           JNC        LAB_004027a9
///         d1 e9           SHR        ECX,0x1
///         eb f3           JMP        LAB_0040279c
///     LAB_004027a9
///         89 c8           MOV        EAX,ECX
///         c3              RET
/// ```

pub fn generate_function_overview(sample_data: &[u8]) -> Result<Vec<(u32, u32)>> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);
    let text_section_header = pe.get_section_by_name(".text")?;
    let bitness = get_bitness_from_pe(&pe);

    let virt_addr_start = text_section_header.virtual_address.0 as usize;
    let raw_addr_start = text_section_header.pointer_to_raw_data.0 as usize;
    let raw_data_size = text_section_header.size_of_raw_data as usize;
    let raw_addr_end = raw_addr_start + raw_data_size;

    let text_section_data = &sample_data[raw_addr_start..raw_addr_end];
    let initial_ip = text_section_header.virtual_address.0 as u64;

    let decoder = Decoder::with_ip(bitness, text_section_data, initial_ip, DecoderOptions::NONE);

    let mut functions: Vec<(u32, u32)> = Vec::new();

    for instruction in decoder
        .into_iter()
        .filter(|i| matches!(i.code(), Code::Call_rel32_32))
    {
        let func_addr = instruction.memory_displacement32();

        if func_addr as usize >= raw_data_size + virt_addr_start {
            continue;
        }

        if !functions.iter().any(|(f, _)| *f == func_addr) {
            let size = get_size_of_function(
                &pe,
                &text_section_data[func_addr as usize - virt_addr_start..],
            );
            functions.push((func_addr, size));
        }
    }
    Ok(functions)
}

/// Gets the size of a function by iterating over the function and looking for a `ret` instruction
pub fn get_size_of_function(pe: &VecPE, start_of_function_data: &[u8]) -> u32 {
    let bitness = get_bitness_from_pe(pe);
    let mut decoder = Decoder::new(bitness, start_of_function_data, DecoderOptions::NONE);

    let mut size = 0;
    if decoder.can_decode() {
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        size += instruction.len() as u32;

        if matches!(instruction.code(), Code::Jmp_rm16)
            || matches!(instruction.code(), Code::Jmp_rm32)
            || matches!(instruction.code(), Code::Jmp_rm64)
        {
            return size;
        }
    }

    for instruction in decoder {
        size += instruction.len() as u32;
        if matches!(instruction.code(), Code::Retnw)
            || matches!(instruction.code(), Code::Retnd)
            || matches!(instruction.code(), Code::Retnq)
        {
            break;
        }
    }

    size
}
