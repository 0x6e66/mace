use anyhow::Result;
use exe::VecPE;
use iced_x86::{Code, Decoder, DecoderOptions};
use yara_x::{Compiler, Scanner};

use crate::{extractor::dmsniff::rules::RULE_PREFIX, utils::get_bitness_from_pe};

pub fn extract_prefix_from_dga_function(pe: &VecPE, function_data: &[u8]) -> Result<String> {
    let mut res = String::new();

    // compile rule and get scan results
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_PREFIX)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(function_data)?;

    let bitness = get_bitness_from_pe(pe);

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            for mat in pattern.matches() {
                let decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);

                // get prefix characters that are moved onto the stack
                for instruction in decoder {
                    if !matches!(instruction.code(), Code::Mov_rm8_imm8) {
                        break;
                    }
                    res.push(instruction.immediate8().into());
                }
            }
        }
    }

    Ok(res)
}
