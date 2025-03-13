mod rules;

use std::io::{Cursor, Read};

use anyhow::{Result, anyhow};
use iced_x86::{Code, Decoder, DecoderOptions};
use yara_x::{Compiler, Scanner};
use zip::ZipArchive;

use crate::configuration::MalwareConfiguration;
use rules::RULE_DGA;

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let cursor = Cursor::new(sample_data);
    let mut archive = ZipArchive::new(cursor)?;

    let filename = archive
        .file_names()
        .find(|filename| filename.contains("lib/x86_64/"))
        .map(|s| s.to_owned());

    if let Some(filename) = filename {
        if let Ok(mut zipfile) = archive.by_name(&filename) {
            let mut buff = Vec::with_capacity(zipfile.size() as usize);
            zipfile.read_to_end(&mut buff)?;
            let (customer, tag) = extract_from_elf(&buff)?;

            let mut config = MalwareConfiguration::from((sample_data, "Coper"));
            if let Some(customer) = customer {
                config
                    .data
                    .dga_parameters
                    .strings
                    .insert("customer".to_string(), customer);
            }

            return Ok(config);
        }
    }

    Err(anyhow!("No file 'lib/x86_64/*.so' found in archive"))
}

fn extract_from_elf(elf_data: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let mut customer: Option<String> = None;
    let mut tag: Option<String> = None;

    let mut compiler = Compiler::new();
    compiler.add_source(RULE_DGA)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(elf_data)?;

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            for mat in pattern.matches() {
                let start = mat.range().start;
                let decoder = Decoder::with_ip(
                    64,
                    &elf_data[start..start + 200],
                    start as u64,
                    DecoderOptions::NONE,
                );
                for instruction in decoder {
                    if matches!(instruction.code(), Code::Movaps_xmm_xmmm128) && customer.is_none()
                    {
                        let offset = instruction.memory_displacement64() as usize;
                        let mut customer_data = elf_data[offset..offset + 16].to_vec();
                        if let Some(i) = customer_data.iter().rposition(|x| *x != 0) {
                            let new_len = i + 1;
                            customer_data.truncate(new_len);
                        }

                        customer = Some(String::from_utf8(customer_data)?);
                    }
                }
            }
        }
    }

    Ok((customer, tag))
}
