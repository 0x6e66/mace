mod rules;

use anyhow::Result;
use exe::{PEType, VecPE};
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{
    configuration::MalwareConfiguration,
    utils::{generate_function_overview, get_bitness_from_pe},
};

use rules::{RULE_PREFIX, RULE_PRIMES};

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);

    let dga_func_candidates = identify_dga_func_candidates(&pe)?;

    let mut primes = vec![];
    let mut prefix = String::new();
    for (_, dga_func_data) in dga_func_candidates {
        if let Ok(tmp_primes) = extract_primes_from_dga_function(&pe, dga_func_data) {
            primes = tmp_primes;
            prefix = extract_prefix_from_dga_function(&pe, dga_func_data).unwrap();
            break;
        }
    }

    let mut config = MalwareConfiguration::from((sample_data, "DMSniff"));

    config
        .data
        .dga_parameters
        .number_sequences
        .insert("primes".to_string(), primes);
    config
        .data
        .dga_parameters
        .strings
        .insert("prefix".to_string(), prefix);

    Ok(config)
}

fn identify_dga_func_candidates(pe: &VecPE) -> Result<Vec<(u32, &[u8])>> {
    let mut function_overview = generate_function_overview(pe)?;

    // average size of the dga function is 447 bytes
    function_overview
        .sort_by(|(_, d1), (_, d2)| d1.len().abs_diff(447).cmp(&d2.len().abs_diff(447)));

    Ok(function_overview)
}

fn extract_prefix_from_dga_function(pe: &VecPE, function_data: &[u8]) -> Result<String> {
    let mut res = String::new();

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
    if res.len() <= 4 {
        return Err(anyhow::anyhow!("Too few primes found"));
    }
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
