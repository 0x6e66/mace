use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::classifier::MalwareFamiliy;

#[derive(Parser, Debug)]
#[command(
    name = "mace",
    version,
    about = "MAlware Configuration Extrator",
    long_about = "mace (MAlware Configuration Extrator) is a program to automatically extract information from a malware sample.
The extraction focused only on information regarding the C2 (Command & Control) communication of the sample.
This includes hardcoded domains and IPs and parameters of used DGAs (Domain Generation Algorithm)."
)]
pub struct Cli {
    #[arg(
        value_parser = validate_file,
        help = "Path to the sample",
        long_help = "Set the path to the sample you want to analyze. The sample you want to analyze can be in a (encrypted) zip file.
For details on this see the option 'mode'."
    )]
    pub file: PathBuf,

    #[arg(
        short,
        long,
        value_enum,
        value_name = "FAMILY",
        help = "Force the use of a specific extractor",
        long_help = "If the automatic detection of the malware family is not working properly for your sample or you know the family
in advance, you can force the extraction for a certain malware family (skipping the automatic detection of the malware family)."
    )]
    pub force_family: Option<MalwareFamiliy>,

    #[arg(
        short,
        long,
        value_enum,
        default_value = "direct",
        help = "Select the mode the file should be treated as",
        long_help = "The mode tells the program how to treat the file.
direct:
    The file is the sample itself (eg. a PE file, ELF file, APK, etc.).
    Note that the files have to be unpacked, because no dynamic analysis is performed.
zipfile:
    The file is a zip file and contains only one file. That one file is the sample.
encrypted-zipfile:
    The file is a password-protected zip file and contains only one file. That one file is the sample.
    The password has to be supplied via the 'password' option."
    )]
    pub mode: Mode,

    #[arg(
        short,
        long,
        value_enum,
        help = "The password for encrypted zip files",
        long_help = "When the sample is in a password-protected zip file, the password can be set with this option",
        required_if_eq("mode", "encrypted-zipfile")
    )]
    pub password: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Mode {
    Direct,
    Zipfile,
    EncryptedZipfile,
}

fn validate_file(s: &str) -> Result<PathBuf, String> {
    let pathbuf = PathBuf::from(s);

    if !pathbuf.exists() {
        return Err("The path does not exists".to_string());
    } else if !pathbuf.is_file() {
        return Err("The specified path is either not a file, permissions are missing or symbolic links are broken".to_string());
    }

    Ok(pathbuf)
}
