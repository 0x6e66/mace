mod metastealer;

use crate::{classifier::MalwareFamiliy, configuration::MalwareConfiguration};

pub fn extract_for_families(
    sample_data: &[u8],
    families: &[MalwareFamiliy],
) -> Vec<MalwareConfiguration> {
    families
        .into_iter()
        .filter_map(|family| extract_internal(sample_data, family))
        .collect()
}

fn extract_internal(sample_data: &[u8], family: &MalwareFamiliy) -> Option<MalwareConfiguration> {
    match family {
        MalwareFamiliy::Metastealer => metastealer::extract(sample_data).ok(),
    }
}
