use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

use serde::{Serialize as SerdeSerialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use sha256::digest;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MalwareConfiguration {
    pub header: Header,
    pub data: Data,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Header {
    pub sha256_of_sample: String,
    pub datetime_of_extraction: String,
    pub extractor_used: String,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Data {
    pub hardcoded_ips: Vec<(IpAddr, Option<u16>)>,
    pub hardcoded_domains: Vec<(String, Option<u16>)>,
    pub dga_parameters: DGAParameters,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct DGAParameters {
    #[serde(serialize_with = "ordered_map")]
    pub number_sequences: HashMap<String, Vec<u32>>,
    #[serde(serialize_with = "ordered_map")]
    pub string_sequences: HashMap<String, Vec<String>>,
    #[serde(serialize_with = "ordered_map")]
    pub strings: HashMap<String, String>,
    #[serde(serialize_with = "ordered_map")]
    pub magic_numbers: HashMap<String, u64>,
}

impl From<(&[u8], &str)> for MalwareConfiguration {
    fn from(value: (&[u8], &str)) -> Self {
        let (data, family) = value;

        let hash = digest(data);
        let dt = chrono::offset::Local::now().to_rfc3339();

        Self {
            header: Header {
                sha256_of_sample: hash,
                datetime_of_extraction: dt,
                extractor_used: family.to_string(),
            },
            ..Default::default()
        }
    }
}

fn ordered_map<S, K: Ord + SerdeSerialize, V: SerdeSerialize>(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}
