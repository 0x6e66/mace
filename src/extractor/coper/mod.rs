mod rules;

use std::io::{Cursor, Read};

use anyhow::{Result, anyhow};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, Register};
use yara_x::{Compiler, Scanner};
use zip::ZipArchive;

use crate::configuration::MalwareConfiguration;
use rules::RULE_DGA;

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let cursor = Cursor::new(sample_data);
    let mut archive = ZipArchive::new(cursor)?;

    // get path of 64-bit elf inside zip archive
    let filename = archive
        .file_names()
        .find(|filename| filename.contains("lib/x86_64/"))
        .map(|s| s.to_owned());

    if let Some(filename) = filename {
        if let Ok(mut zipfile) = archive.by_name(&filename) {
            // read data of elf to buffer
            let mut buff = Vec::with_capacity(zipfile.size() as usize);
            zipfile.read_to_end(&mut buff)?;

            // get customer and tag from buffer
            let (customer, tag) = extract_from_elf(&buff)?;

            // create malware config from sample data
            let mut config = MalwareConfiguration::from((sample_data, "Coper"));

            // add customer to config
            if let Some(customer) = customer {
                config
                    .data
                    .dga_parameters
                    .strings
                    .insert("customer".to_string(), customer);
            }

            // add tag to config
            if let Some(tag) = tag {
                config
                    .data
                    .dga_parameters
                    .strings
                    .insert("tag".to_string(), tag);
            }

            return Ok(config);
        }
    }

    Err(anyhow!("No file 'lib/x86_64/*.so' found in archive"))
}

/// extract `customer` and `tag` from elf data
fn extract_from_elf(elf_data: &[u8]) -> Result<(Option<String>, Option<String>)> {
    // compile yara rule and get results from scanner
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_DGA)?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(elf_data)?;

    // get match for rule that identifies the 'make_DGA' stack string in the sample
    let mat = results
        .matching_rules()
        .next()
        .and_then(|r| r.patterns().next())
        .and_then(|p| p.matches().next())
        .ok_or(anyhow!("could not find 'make_DGA' in binary"))?;

    // simulate the stack to get customer und tag data
    let stack = simulate_stack(elf_data, mat.range().start);

    // extract the first two strings (separated by null bytes) from the stack
    let strings: Vec<String> = stack
        .split(|s| *s == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .collect();

    let tag = strings.first().cloned();
    let customer = strings.get(1).cloned();

    Ok((customer, tag))
}

/// simulate the data on the stack for the instructions starting at `start`
fn simulate_stack(elf_data: &[u8], start: usize) -> [u8; 100] {
    let mut stack = [0u8; 100];

    // create decoder to get iterator over instructions from byte slice
    let decoder = Decoder::with_ip(
        64,
        &elf_data[start..start + 200],
        start as u64,
        DecoderOptions::NONE,
    );

    // temporary containers for register data for rax and xmm
    let mut xmm_reg = Vec::new();
    let mut rax_reg = Vec::new();

    for instruction in decoder.into_iter().skip(1) {
        // if call instruction is reached, the necessary data is already on the stack
        if matches!(instruction.mnemonic(), Mnemonic::Call) {
            break;
        }
        match instruction.code() {
            // read data from data section into xmm register
            Code::Movaps_xmm_xmmm128 => {
                let offset = instruction.memory_displacement64() as usize;
                let data = elf_data[offset..offset + 16].to_vec();

                xmm_reg = data;
            }
            // move data from xmm register onto the stack
            Code::Movaps_xmmm128_xmm => {
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in xmm_reg.iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            // read data from data section into rax register
            Code::Mov_r64_imm64 => {
                let displ_data = instruction.memory_displacement32().to_le_bytes();
                let immediate_data = instruction.immediate32().to_le_bytes();

                rax_reg = [immediate_data, displ_data].concat();
            }
            // move data from rax register onto the stack
            Code::Mov_rm64_r64 => {
                if matches!(instruction.memory_base(), Register::None)
                    || !(matches!(instruction.op0_register(), Register::None)
                        && matches!(instruction.op1_register(), Register::RAX))
                {
                    continue;
                }
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in rax_reg.iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            // move immediate data onto stack
            Code::Mov_rm32_imm32 => get_from_immediate(&mut stack, &instruction, 32),
            Code::Mov_rm16_imm16 => get_from_immediate(&mut stack, &instruction, 16),
            Code::Mov_rm8_imm8 => get_from_immediate(&mut stack, &instruction, 8),
            _ => (),
        }
    }

    stack
}

/// move data from immediate instruction onto the stack
fn get_from_immediate(stack: &mut [u8], instruction: &Instruction, size: u32) {
    let base = instruction.memory_displacement64() as usize;

    let immediate = match size {
        8 => instruction.immediate8().to_le_bytes().to_vec(),
        16 => instruction.immediate16().to_le_bytes().to_vec(),
        32 => instruction.immediate32().to_le_bytes().to_vec(),
        _ => unreachable!(),
    };

    for (i, e) in immediate.iter().enumerate() {
        stack[base + i] = *e;
    }
}
