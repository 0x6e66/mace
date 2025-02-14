mod rules;

use anyhow::Result;
use exe::{PEType, VecPE};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{
    configuration::MalwareConfiguration,
    utils::{generate_function_overview, get_bitness_from_pe},
};

use rules::RULE_PRIMES;

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);

    let (_, dga_func_data) = identify_dga_func(&pe)?;
    let primes = extract_primes_from_dga_function(&pe, dga_func_data).unwrap();

    let mut config = MalwareConfiguration::from((sample_data, "DMSniff"));

    config
        .data
        .dga_parameters
        .number_sequences
        .insert("primes".to_string(), primes);

    Ok(config)
}

fn identify_dga_func(pe: &VecPE) -> Result<(u32, &[u8])> {
    let function_overview = generate_function_overview(pe)?;

    // TODO: change to proper detection mechanism
    let res = *function_overview
        .into_iter()
        .filter(|(f, _)| *f == 0x2168 || *f == 0x335a)
        .collect::<Vec<(u32, &[u8])>>()
        .first()
        .ok_or(anyhow::anyhow!("Could not locale DGA function"))?;

    Ok(res)
}

fn extract_primes_from_dga_function(pe: &VecPE, function_data: &[u8]) -> Result<Vec<u32>> {
    let mut tmp: Vec<(u32, usize)> = Vec::new();

    let mut compiler = Compiler::new();
    compiler.add_source(RULE_PRIMES)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(function_data)?;

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            match pattern.identifier() {
                "$sequence_eax" => {
                    for mat in pattern.matches() {
                        let p = extract_prime_from_eax(pe, mat.data())?;
                        let r = mat.range().start;
                        tmp.push((p, r));
                    }
                }
                "$sequence_edi" => {
                    for mat in pattern.matches() {
                        let r = mat.range().start;
                        tmp.push((1, r));
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    tmp.sort_by(|(_, s1), (_, s2)| s1.cmp(s2));

    let mut res = tmp.into_iter().map(|(p, _)| p).collect::<Vec<u32>>();
    res.truncate(res.len() - 4);

    Ok(res)
}

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
