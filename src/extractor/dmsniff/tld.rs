use anyhow::Result;
use exe::{VecPE, PE};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use yara_x::{Compiler, Scanner};

use crate::{
    extractor::dmsniff::rules::{RULE_KEYS, RULE_TLDS},
    utils::{generate_function_overview, get_bitness_from_pe, virtual_to_raw_address, Function},
};

pub fn extract_tlds_from_dga_func(pe: &VecPE, dga_func: &Function) -> Result<Vec<String>> {
    let function_overview = generate_function_overview(pe)?;
    let data_section_header = pe.get_section_by_name(".data")?;
    let bitness = get_bitness_from_pe(pe);
    let image_base = pe.get_image_base()? as u32;

    let mut compiler = Compiler::new();
    compiler.add_source(RULE_TLDS)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&dga_func.data)?;

    let mut decrypt_string_function = None;
    let mut encrypted_tlds: Vec<Vec<u8>> = Vec::new();

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            for mat in pattern.matches() {
                let ip = dga_func.address + mat.range().start as u32;
                let decoder =
                    Decoder::with_ip(bitness, mat.data(), ip.into(), DecoderOptions::NONE);

                for instrunction in decoder {
                    match instrunction.mnemonic() {
                        Mnemonic::Push => {
                            let address = instrunction.immediate32() - image_base;
                            let address =
                                virtual_to_raw_address(data_section_header, address) as usize;
                            let end = address + (&pe.get_buffer()[address] + 4) as usize;
                            encrypted_tlds.push(pe.get_buffer()[address..end].to_vec());
                        }
                        Mnemonic::Call => {
                            if decrypt_string_function.is_none() {
                                let addr = instrunction.memory_displacement32();
                                if let Some(func) =
                                    function_overview.iter().find(|f| f.address == addr)
                                {
                                    decrypt_string_function = Some(func);
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    let mut tlds = vec![];

    if let Some(function) = decrypt_string_function {
        let (key1, key2) = get_keys_from_decrypt_string_function(pe, function)?;
        for dt in &mut encrypted_tlds {
            decrypt(dt, key1, key2);
            let mut s = String::from_utf8(dt[3..].to_vec()).unwrap();
            s.pop();
            tlds.push(s);
        }
    }

    Ok(tlds)
}

fn get_keys_from_decrypt_string_function<'a>(
    pe: &'a VecPE,
    function: &Function,
) -> Result<(u8, &'a [u8])> {
    let bitness = get_bitness_from_pe(pe);
    let data_section_header = pe.get_section_by_name(".data")?;
    let image_base = pe.get_image_base()? as u32;

    let mut compiler = Compiler::new();
    compiler.add_source(RULE_KEYS)?;

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&function.data)?;

    let mut key1 = 255;
    let mut mem_displ = 0;

    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            for mat in pattern.matches() {
                let decoder = Decoder::new(bitness, mat.data(), DecoderOptions::NONE);

                for instrunction in decoder {
                    match instrunction.mnemonic() {
                        Mnemonic::Movzx => mem_displ = instrunction.memory_displacement32(),
                        Mnemonic::Mov => key1 = instrunction.immediate32(),
                        Mnemonic::And => key1 = instrunction.immediate32(),
                        _ => (),
                    }
                }
            }
        }
    }

    let index = virtual_to_raw_address(data_section_header, mem_displ - image_base) as usize;
    let key2 = &pe.get_buffer()[index..index + key1 as usize];

    Ok((key1 as u8, key2))
}

fn decrypt(bytes: &mut [u8], key1: u8, key2: &[u8]) {
    let index_0 = bytes[0];
    let index_2 = bytes[2];

    for i in 3..index_0 as usize + 3 {
        bytes[i] ^= key2[i % key1 as usize];
        bytes[i] ^= index_2;
    }
    bytes[0] = 0;
    bytes[1] = 0;
}
