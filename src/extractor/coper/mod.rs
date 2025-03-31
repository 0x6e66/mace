mod rules;

use std::io::{Cursor, Read};

use anyhow::{Result, anyhow};
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, Register};
use yara_x::{Compiler, Scanner};
use zip::ZipArchive;

use crate::configuration::MalwareConfiguration;
use rules::RULE_DGA;

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let cursor = Cursor::new(sample_data);
    let mut archive = ZipArchive::new(cursor)?;

    // get path of 64-bit elf
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

fn extract_from_elf(elf_data: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_DGA)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(elf_data)?;

    let mut stack = [0u8; 100];

    let mat = results
        .matching_rules()
        .next()
        .and_then(|r| r.patterns().next())
        .and_then(|p| p.matches().next())
        .ok_or(anyhow!("could not find 'make_DGA' in binary"))?;

    let start = mat.range().start;
    let decoder = Decoder::with_ip(
        64,
        &elf_data[start..start + 200],
        start as u64,
        DecoderOptions::NONE,
    );

    let mut xmm_data = Vec::new();
    let mut rax_data = Vec::new();

    // for each instruction get data that will be put on the stack
    for instruction in decoder.into_iter().skip(1) {
        if matches!(instruction.mnemonic(), Mnemonic::Call) {
            break;
        }
        match instruction.code() {
            Code::Movaps_xmm_xmmm128 => {
                let offset = instruction.memory_displacement64() as usize;
                let data = elf_data[offset..offset + 16].to_vec();

                xmm_data = data;
            }
            Code::Movaps_xmmm128_xmm => {
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in xmm_data.iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            Code::Mov_r64_imm64 => {
                let displ_data = instruction.memory_displacement32().to_le_bytes();
                let immediate_data = instruction.immediate32().to_le_bytes();

                rax_data = [immediate_data, displ_data].concat();
            }
            Code::Mov_rm64_r64 => {
                if matches!(instruction.memory_base(), Register::None)
                    || !(matches!(instruction.op0_register(), Register::None)
                        && matches!(instruction.op1_register(), Register::RAX))
                {
                    continue;
                }
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in rax_data.iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            Code::Mov_rm32_imm32 => {
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in instruction.immediate32().to_le_bytes().iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            Code::Mov_rm16_imm16 => {
                let base = instruction.memory_displacement64() as usize;

                for (i, e) in instruction.immediate16().to_le_bytes().iter().enumerate() {
                    stack[base + i] = *e;
                }
            }
            Code::Mov_rm8_imm8 => {
                let base = instruction.memory_displacement64() as usize;

                stack[base] = instruction.immediate8();
            }
            _ => (),
        }
    }

    let tmp: Vec<String> = stack
        .split(|s| *s == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .collect();

    let tag = tmp.first().cloned();
    let customer = tmp.get(1).cloned();

    Ok((customer, tag))
}
