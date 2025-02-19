mod counter;
mod prefix;
mod primes;
mod rules;
mod tld;

use anyhow::Result;
use exe::{PEType, VecPE};
use tld::extract_tlds_from_dga_func;

use crate::{
    configuration::MalwareConfiguration,
    extractor::dmsniff::{
        counter::extract_counter_from_call_dga_func, prefix::extract_prefix_from_dga_function,
        primes::extract_primes_from_dga_function,
    },
    utils::{generate_function_overview, Function},
};

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);
    let mut function_overview = generate_function_overview(&pe)?;

    // average size of the dga function is 447 bytes
    function_overview.sort_by(|f1, f2| {
        f1.data
            .len()
            .abs_diff(447)
            .cmp(&f2.data.len().abs_diff(447))
    });

    let mut primes = vec![];
    let mut prefix = String::new();
    let mut counter = 0;
    let mut tlds = vec![];

    for dga_func in &function_overview {
        if let Ok(tmp_primes) = extract_primes_from_dga_function(&pe, &dga_func.data) {
            primes = tmp_primes;
            prefix = extract_prefix_from_dga_function(&pe, &dga_func.data)?;
            tlds = extract_tlds_from_dga_func(&pe, dga_func)?;

            for f in function_overview
                .iter()
                .filter(|Function { function_calls, .. }| {
                    function_calls.contains(&dga_func.address)
                })
            {
                if let Ok(tmp_counter) = extract_counter_from_call_dga_func(&pe, &f.data) {
                    counter = tmp_counter;
                    break;
                }
            }
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
    config
        .data
        .dga_parameters
        .magic_numbers
        .insert("counter".to_string(), counter.into());
    config
        .data
        .dga_parameters
        .string_sequences
        .insert("tlds".to_string(), tlds);

    Ok(config)
}
