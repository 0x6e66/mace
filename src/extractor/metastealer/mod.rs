mod rules;

use anyhow::{Result, anyhow};
use exe::{Buffer, PEType, VecPE};
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{
    configuration::MalwareConfiguration,
    extractor::metastealer::rules::{RULE_PARAMS, RULE_SEED},
    utils::get_bitness_from_pe,
};

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);

    // extract seeds and other dga parameters
    let seed = get_seed(&pe).ok_or(anyhow!("seed not found"))?;
    let params = get_dga_params(&pe).ok_or(anyhow!("dga parameters not found"))?;

    // get config from sample data
    let mut res = MalwareConfiguration::from((sample_data, "Metastealer"));
    let mn = &mut res.data.dga_parameters.magic_numbers;

    // add seed and parameters to config
    mn.insert("seed".to_string(), seed);
    mn.insert("num_of_domains".to_string(), params.num.into());
    mn.insert("mul_value".to_string(), params.mul.into());
    mn.insert("len_of_domain".to_string(), params.len.into());
    mn.insert("and_value".to_string(), params.and.into());
    mn.insert("div_value".to_string(), params.div.into());
    mn.insert("add_value".to_string(), params.add.into());
    mn.insert("xor_value".to_string(), params.xor.into());

    Ok(res)
}

#[derive(Debug)]
struct DgaParams {
    pub num: u32,
    pub mul: u32,
    pub len: u32,
    pub and: u32,
    pub div: u32,
    pub add: u8,
    pub xor: u8,
}

fn get_dga_params(pe: &VecPE) -> Option<DgaParams> {
    let bitness = get_bitness_from_pe(pe);

    // compile yara rule and get results from scanner
    let mut compiler = Compiler::new();
    compiler.add_source(RULE_PARAMS).ok()?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(pe.get_buffer().as_slice()).ok()?;

    let mut num: Option<u32> = None;
    let mut mul: Option<u32> = None;
    let mut len: Option<u32> = None;
    let mut and: Option<u32> = None;
    let mut div: Option<u32> = None;
    let mut add: Option<u8> = None;
    let mut xor: Option<u8> = None;

    for r in results.matching_rules() {
        for pat in r.patterns() {
            for mat in pat.matches() {
                let decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);

                for instruction in decoder {
                    match instruction.code() {
                        Code::Cmp_rm32_imm32 if num.is_none() => {
                            num = Some(instruction.immediate32());
                        }
                        Code::Imul_r32_rm32_imm32 if mul.is_none() => {
                            mul = Some(instruction.immediate32());
                        }
                        Code::Mov_rm32_imm32 if len.is_none() && instruction.len() == 10 => {
                            len = Some(instruction.immediate32());
                        }
                        Code::And_EAX_imm32 if and.is_none() => {
                            and = Some(instruction.immediate32());
                        }
                        Code::Mov_r32_imm32 if div.is_none() && instruction.immediate32() != 0 => {
                            div = Some(instruction.immediate32());
                        }
                        Code::Add_rm8_imm8 if add.is_none() => {
                            add = Some(instruction.immediate8());
                        }
                        Code::Xor_rm32_imm8 if xor.is_none() => {
                            xor = Some(instruction.immediate8());
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    Some(DgaParams {
        num: num?,
        mul: mul?,
        len: len?,
        and: and?,
        div: div?,
        add: add?,
        xor: xor?,
    })
}

fn get_seed(pe: &VecPE) -> Option<u64> {
    let bitness = get_bitness_from_pe(pe);

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
            .filter(|i| matches!(i.mnemonic(), Mnemonic::Push))
            .find(|i| ![0x6ef, 0].contains(&i.immediate32()))
        {
            return Some(instruction.immediate64());
        }
    }

    None
}
