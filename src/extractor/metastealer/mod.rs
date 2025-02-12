mod yara_rule;

use anyhow::{anyhow, Result};
use exe::{PEType, VecPE, PE};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use yara_rule::RULE;

use crate::configuration::MalwareConfiguration;

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let seed = get_seed(sample_data).ok_or(anyhow!("seed not found"))?;

    let mut res = MalwareConfiguration::from((sample_data, "Metastealer"));

    res.data
        .dga_parameters
        .magic_numbers
        .insert("seed".to_string(), seed);

    Ok(res)
}

fn get_seed(sample_data: &[u8]) -> Option<u64> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);
    let bitness = match pe.get_valid_nt_headers().ok()? {
        exe::NTHeaders::NTHeaders32(_) => 32,
        exe::NTHeaders::NTHeaders64(_) => 64,
    };

    let mut compiler = Compiler::new();
    compiler.add_source(RULE).ok()?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(sample_data).ok()?;

    for r in results.matching_rules() {
        for pat in r.patterns() {
            for mat in pat.matches() {
                let decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);
                if let Some(instruction) = decoder
                    .into_iter()
                    .filter(|i| matches!(i.mnemonic(), Mnemonic::Push))
                    .find(|i| ![0x6ef, 0].contains(&i.immediate32()))
                {
                    return Some(instruction.immediate64());
                }
            }
        }
    }

    None
}
