use anyhow::Result;
use exe::VecPE;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{extractor::dmsniff::rules::RULE_PRIMES, utils::get_bitness_from_pe};

pub fn extract_primes_from_dga_function(pe: &VecPE, function_data: &[u8]) -> Result<Vec<u32>> {
    let mut prime_positions: Vec<(u32, usize)> = Vec::new();

    // compile rule and get scan results
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_PRIMES)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(function_data)?;

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            // extract prime and store itself and its position
            match pattern.identifier() {
                "$sequence_eax" => {
                    for mat in pattern.matches() {
                        let p = extract_prime_from_eax(pe, mat.data())?;
                        let pos = mat.range().start;
                        prime_positions.push((p, pos));
                    }
                }
                "$sequence_edi" => {
                    for mat in pattern.matches() {
                        let pos = mat.range().start;
                        prime_positions.push((1, pos));
                    }
                }
                "$sequence_shift" => {
                    for mat in pattern.matches() {
                        let pos = mat.range().start;
                        prime_positions.push((2, pos));
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    // sort primes by position
    prime_positions.sort_by(|(_, s1), (_, s2)| s1.cmp(s2));

    // discard positions
    let mut res = prime_positions
        .into_iter()
        .map(|(p, _)| p)
        .collect::<Vec<u32>>();

    // get the first 5 primes
    if res.len() <= 4 + 5 {
        return Err(anyhow::anyhow!("Too few primes found"));
    }
    res.truncate(res.len() - 4);

    Ok(res)
}

/// deal with special case of prime being moved into eax register
fn extract_prime_from_eax(pe: &VecPE, snippet: &[u8]) -> Result<u32> {
    let bitness = get_bitness_from_pe(pe);
    let mut decoder = Decoder::new(bitness, snippet, DecoderOptions::NONE);

    let instruction = decoder.decode();

    match instruction.mnemonic() {
        Mnemonic::Mov => Ok(instruction.immediate32()),
        Mnemonic::Lea => Ok(5),
        _ => unreachable!(),
    }
}
