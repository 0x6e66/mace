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

impl Commands {
    pub fn get_global_args(&self) -> &GlobalArgs {
        match self {
            Self::Direct(DirectArgs { global_args }) => global_args,
            Self::Zip(ZipArgs { global_args, .. }) => global_args,
        }
    }
}

#[derive(Args, Debug)]
pub struct GlobalArgs {
    #[arg(
        short,
        long,
        value_enum,
        value_name = "FAMILY",
        help = "Specify the malware family of the sample you are trying to analyze"
    )]
    pub family: MalwareFamiliy,

    #[arg(
        value_parser = validate_file,
        help = "Path to the sample",
        long_help = "Set the path to the sample you want to analyze"
    )]
    pub files: Vec<PathBuf>,

    #[arg(short, long, help = "Set file output should be written to")]
    pub output: Option<PathBuf>,
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
