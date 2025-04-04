mod counter;
mod prefix;
mod primes;
mod rules;
mod tld;

use anyhow::Result;
use exe::{PEType, VecPE};

use crate::{
    configuration::MalwareConfiguration,
    extractor::dmsniff::{
        counter::extract_counter_from_call_dga_func, prefix::extract_prefix_from_dga_function,
        primes::extract_primes_from_dga_function, tld::extract_tlds_from_dga_func,
    },
    utils::generate_function_overview,
};

pub fn extract(sample_data: &[u8]) -> Result<MalwareConfiguration> {
    let pe = VecPE::from_data(PEType::Disk, sample_data);
    let mut function_overview = generate_function_overview(&pe)?;

    // sort functions by size (average size of the dga function is 447 bytes) for better
    // performance
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

    let mut found = false;

    for dga_func in &function_overview {
        // try extract primes from function
        if let Ok(tmp_primes) = extract_primes_from_dga_function(&pe, &dga_func.data) {
            primes = tmp_primes;

            // extract prefix and tlds from dga function
            prefix = extract_prefix_from_dga_function(&pe, &dga_func.data)?;
            tlds = extract_tlds_from_dga_func(&pe, dga_func)?;

            // find function that calls the dga function
            for f in function_overview
                .iter()
                .filter(|f| f.function_calls.contains(&dga_func.address))
            {
                // try extract the number of domains generated from function
                if let Ok(tmp_counter) = extract_counter_from_call_dga_func(&pe, &f.data) {
                    counter = tmp_counter;
                    break;
                }
            }
            found = true;
            break;
        }
    }

    if !found {
        return Err(anyhow::anyhow!("Could not find dga function"));
    }

    // create malware config from sample data
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
