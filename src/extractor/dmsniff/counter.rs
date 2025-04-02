use anyhow::Result;
use exe::VecPE;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{extractor::dmsniff::rules::RULE_COUNTER, utils::get_bitness_from_pe};

pub fn extract_counter_from_call_dga_func(pe: &VecPE, function_data: &[u8]) -> Result<u32> {
    let bitness = get_bitness_from_pe(pe);

    // compile rule and get scan results
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_COUNTER)?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(function_data)?;

    if let Some(mat) = results
        .matching_rules()
        .next()
        .and_then(|r| r.patterns().next())
        .and_then(|p| p.matches().next())
    {
        let mut decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);

        if !decoder.can_decode() {
            return Err(anyhow::anyhow!("Could not find counter"));
        }

        // extract counter
        let instruction = decoder.decode();
        match instruction.mnemonic() {
            Mnemonic::Mov => return Ok(instruction.immediate32()),
            Mnemonic::Cmp => return Ok(instruction.immediate32()),
            _ => unreachable!(),
        }
    }

    Err(anyhow::anyhow!("Could not find counter"))
}
