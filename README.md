# MACE (MAlware Configuration Extrator)
[![Crate](https://img.shields.io/crates/v/mace.svg)](https://crates.io/crates/mace)
[![Documentation](https://img.shields.io/docsrs/mace?label=docs.rs)](https://docs.rs/mace)
![License](https://img.shields.io/crates/l/mace)

## Description
This project aims to provide functionality for the automated extraction of malware configuration from samples. The extracted information is focused on the C2 communication of the sample.
This includes hardcoded domains and IPs and parameters of used Domain Generation Algorithms.

## Supported malware families
> Note: Automatic classification of malware families is not yet implemented
- [Coper](https://malpedia.caad.fkie.fraunhofer.de/details/apk.coper)
- [DMSniff](https://malpedia.caad.fkie.fraunhofer.de/details/win.dmsniff)
- [MetaStealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.metastealer)

## Example usage
Analyzing the DMSniff sample [f4be1b8d67e33c11789d151d288130254d346ecc0f4738a12ce3a34d86ec646d](https://www.virustotal.com/gui/file/f4be1b8d67e33c11789d151d288130254d346ecc0f4738a12ce3a34d86ec646d)
```bash
$ cargo run -- direct -f dm-sniff sample.exe | jq
{
  "header": {
    "sha256_of_sample": "f4be1b8d67e33c11789d151d288130254d346ecc0f4738a12ce3a34d86ec646d",
    "datetime_of_extraction": "2025-03-31T18:27:17.391055677+02:00",
    "extractor_used": "DMSniff"
  },
  "data": {
    "hardcoded_ips": [],
    "hardcoded_domains": [],
    "dga_parameters": {
      "number_sequences": {
        "primes": [
          5,
          3,
          1,
          7,
          13,
          11
        ]
      },
      "string_sequences": {
        "tlds": [
          ".com",
          ".org",
          ".net",
          ".ru",
          ".in"
        ]
      },
      "strings": {
        "prefix": "st"
      },
      "magic_numbers": {
        "counter": 50
      }
    }
  }
}
```

## Todo
- [ ] Implement automated classification of malware families

