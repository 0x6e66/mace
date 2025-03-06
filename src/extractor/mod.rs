mod dmsniff;
mod metastealer;

use anyhow::Result;

use crate::{classifier::MalwareFamiliy, configuration::MalwareConfiguration};

pub fn extract_for_family(
    sample_data: &[u8],
    family: &MalwareFamiliy,
) -> Result<MalwareConfiguration> {
    match family {
        MalwareFamiliy::Metastealer => metastealer::extract(sample_data),
        MalwareFamiliy::DMSniff => dmsniff::extract(sample_data),
    }
}
