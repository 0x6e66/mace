use anyhow::{anyhow, Result};
use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum MalwareFamiliy {
    Copper,
    Bumblebee,
}

pub fn classify_sample(sample_data: &[u8]) -> Result<Vec<MalwareFamiliy>> {
    Err(anyhow!("TODO"))
}
