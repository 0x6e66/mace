mod rules;

use anyhow::{Result, anyhow};
use exe::{Buffer, PEType, VecPE};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction};
use yara_x::{Compiler, Scanner};

use crate::{configuration::MalwareConfiguration, extractor::metastealer::rules::RULE_SEED};

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);

    // extract seeds and other dga parameters
    let seed = get_seed(&pe).ok_or(anyhow!("seed not found"))?;

    // get config from sample data
    let mut res = MalwareConfiguration::from((sample_data, "Metastealer"));
    let mn = &mut res.data.dga_parameters.magic_numbers;

    // add seed and parameters to config
    mn.insert("seed".to_string(), seed);

    Ok(res)
}

fn get_seed(pe: &VecPE) -> Option<u64> {
    let bitness = 32;

    // compile yara rule and get results from scanner
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_SEED).ok()?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(pe.get_buffer().as_slice()).ok()?;

    // if rule matches get seed
    if let Some(mat) = results
        .matching_rules()
        .next()
        .and_then(|r| r.patterns().next())
        .and_then(|p| p.matches().next())
    {
        // get seed from push instruction
        let decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);
        if let Some(instruction) = decoder
            .into_iter()
            .filter(|i| matches!(i.code(), Code::Pushd_imm32))
            .collect::<Vec<Instruction>>()
            .last()
        {
            return Some(instruction.immediate64());
        }
    }

    None
}
