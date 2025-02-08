use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Pass the sample directly",
        long_about = "With this command the sample has to be passed directly"
    )]
    Direct(DirectArgs),

    #[command(
        about = "Pass the sample in a (encrypted) zipfile",
        long_about = "With this command the sample is passed in a (possibly encrypted) zip file. This could be useful if the sample
might get quarantined by an anti-virus."
    )]
    Zip(ZipArgs),
}

#[derive(Args, Debug)]
pub struct GlobalArgs {
    #[arg(
        short,
        long,
        global = true,
        value_enum,
        value_name = "FAMILY",
        help = "Force the use of a specific extractor",
        long_help = "If the automatic detection of the malware family is not working properly for your sample or you know the family
in advance, you can force the extraction for a certain malware family (skipping the automatic detection of the malware family)."
    )]
    pub force_family: Option<MalwareFamiliy>,

    #[arg(
        value_parser = validate_file,
        help = "Path to the sample",
        long_help = "Set the path to the sample you want to analyze"
    )]
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct DirectArgs {
    #[command(flatten)]
    pub global_args: GlobalArgs,
}

#[derive(Args, Debug)]
pub struct ZipArgs {
    #[command(flatten)]
    pub global_args: GlobalArgs,

    #[arg(
        short,
        long,
        help = "The password for encrypted zip files",
        long_help = "When a password is specified, the program tries to decrypt the sample inside the zip file"
    )]
    pub password: Option<String>,

    #[arg(
        short,
        long,
        help = "Select the name of the sample inside the zip file (when multiple files are present inside the zip file)",
        long_help = "When multiple files are present inside the zip file, a specific one can be selected for analysis.
If multiple files are present and the option is not set, the first one will be selected"
    )]
    pub sample_name: Option<String>,
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
