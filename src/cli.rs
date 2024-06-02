use std::path::PathBuf;

use clap::{arg, command, Arg, ArgAction, Command};
use color_eyre::eyre::bail;
use color_eyre::Result;
use secrecy::SecretString;
use tracing::Level;

use crate::app::{
    Argon2Parameters, EncryptionParameters, InputFilePath, Operation, OutputFilePath, Passphrase,
};

#[derive(Debug)]
pub struct Config {
    pub operation: Operation,
    pub verbosity: tracing::Level,
}

pub fn initialize() -> Result<Config> {
    let matches = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("passphrase")
                .short('k')
                .long("passphrase")
                .help("Passphrase for operations"),
        )
        // TODO: Actually parse and verify integer parameters here
        .arg(
            Arg::new("m_cost")
                // Default recommended Argon2 parameters
                .default_value("19456")
                .short('m')
                .long("memory_cost")
                .help("Memory cost for key derivation"),
        )
        .arg(
            Arg::new("t_cost")
                // Default recommended Argon2 parameters
                .default_value("2")
                .short('t')
                .long("time_cost")
                .help("Time cost for key derivation"),
        )
        .arg(
            Arg::new("p_cost")
                // Default recommended Argon2 parameters
                .default_value("1")
                .short('p')
                .long("parallelism_cost")
                .help("Parallelism for key derivation"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .global(true)
                .help("Increase logging verbosity"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .global(true)
                .conflicts_with("verbose")
                .help("Silences output"),
        )
        .subcommand(
            Command::new("info")
                .visible_alias("i")
                .about("Get information about file")
                .arg(arg!(<input_file_path> "Valid input file path")),
        )
        .subcommand(
            Command::new("extract_additional_data")
                .visible_alias("x")
                .about("Extract additional data from file")
                .arg(arg!(<input_file_path> "Valid input file path"))
                .arg(arg!(<output_folder_path> "Valid output folder path")),
        )
        .subcommand(
            Command::new("verify")
                .visible_alias("v")
                .about("Verify encrypted file")
                .arg(arg!(<input_file_path> "Valid input file path")),
        )
        .subcommand(
            Command::new("encrypt")
                .visible_alias("e")
                .about("Encrypt file")
                .arg(arg!(<input_file_path> "Valid input file path"))
                .arg(arg!(<output_file_path> "Valid output file path")),
        )
        .subcommand(
            Command::new("encrypt_with_additional_data")
                .visible_alias("ea")
                .about("Encrypt file with additional data")
                .arg(arg!(<additional_input_file_path> "Valid input file path for additional data"))
                .arg(arg!(<input_file_path> "Valid input file path"))
                .arg(arg!(<output_file_path> "Valid output file path")),
        )
        .subcommand(
            Command::new("decrypt")
                .visible_alias("d")
                .about("Decrypts encrypted file")
                .arg(arg!(<input_file_path> "Valid input file path"))
                .arg(arg!(<output_file_path> "Valid output file path")),
        )
        .get_matches();

    // Get verbosity level from cli parameters
    let verbosity = match (matches.get_flag("quiet"), matches.get_count("verbose")) {
        // Default while developing
        (false, 0) => Level::INFO,

        (false, 1) => Level::WARN,
        (false, 2) => Level::INFO,
        (false, 3) => Level::DEBUG,
        (false, _) => Level::TRACE,
        // Always show at least errors
        (_, _) => Level::ERROR,
    };

    // Extract parameters for config
    let passphrase = {
        matches
            .get_one::<String>("passphrase")
            .cloned()
            .map(|pp| Passphrase(SecretString::new(pp)))
    };
    let m = {
        // TODO: using double defaults is problematic
        // Default recommended Argon2 parameters
        matches
            .get_one::<String>("m_cost")
            .cloned()
            .and_then(|pp| pp.parse::<u32>().ok())
            .unwrap_or(19456)
    };
    let t = {
        // TODO: using double defaults is problematic
        // Default recommended Argon2 parameters
        matches
            .get_one::<String>("t_cost")
            .cloned()
            .and_then(|pp| pp.parse::<u32>().ok())
            .unwrap_or(2)
    };
    let p = {
        // TODO: using double defaults is problematic
        // Default recommended Argon2 parameters
        matches
            .get_one::<String>("p_cost")
            .cloned()
            .and_then(|pp| pp.parse::<u8>().ok())
            .unwrap_or(1)
    };

    // TODO: Needs to check if paths are valid for files and folders
    let operation = match matches.subcommand() {
        Some(("info", sub_matches)) => {
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            Operation::Information(InputFilePath(PathBuf::from(input_file_path)))
        }
        Some(("extract_additional_data", sub_matches)) => {
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            let output_folder_path = sub_matches
                .get_one::<String>("output_folder_path")
                .expect("String parses any input")
                .to_owned();
            Operation::ExtractAdditionalData(
                InputFilePath(PathBuf::from(input_file_path)),
                OutputFilePath(PathBuf::from(output_folder_path)),
            )
        }
        Some(("verify", sub_matches)) => {
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            if let Some(pp) = passphrase {
                Operation::Verify(pp, InputFilePath(PathBuf::from(input_file_path)))
            } else {
                bail!("Operation requires passphrase")
            }
        }
        Some(("encrypt", sub_matches)) => {
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            let output_file_path = sub_matches
                .get_one::<String>("output_file_path")
                .expect("String parses any input")
                .to_owned();
            if let Some(pp) = passphrase {
                let input = InputFilePath(PathBuf::from(input_file_path));
                let output = OutputFilePath(PathBuf::from(output_file_path));

                if let Ok(argon2_parameters) = Argon2Parameters::new(m, t, p) {
                    let ep = EncryptionParameters {
                        input,
                        additional_data: None,
                        output,
                        argon2_parameters,
                    };
                    Operation::Encrypt(pp, ep)
                } else {
                    bail!("Operation requires valid Argon2 parameters")
                }
            } else {
                bail!("Operation requires passphrase")
            }
        }
        // TODO: Can be combined more elegantly with previous encrypt with optional parameter
        Some(("encrypt_with_additional_data", sub_matches)) => {
            let additional_input_file_path = sub_matches
                .get_one::<String>("additional_input_file_path")
                .expect("String parses any input")
                .to_owned();
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            let output_file_path = sub_matches
                .get_one::<String>("output_file_path")
                .expect("String parses any input")
                .to_owned();
            if let Some(pp) = passphrase {
                let additional_data =
                    Some(InputFilePath(PathBuf::from(additional_input_file_path)));
                let input = InputFilePath(PathBuf::from(input_file_path));
                let output = OutputFilePath(PathBuf::from(output_file_path));

                if let Ok(argon2_parameters) = Argon2Parameters::new(m, t, p) {
                    let ep = EncryptionParameters {
                        input,
                        additional_data,
                        output,
                        argon2_parameters,
                    };
                    Operation::Encrypt(pp, ep)
                } else {
                    bail!("Operation requires valid Argon2 parameters")
                }
            } else {
                bail!("Operation requires passphrase")
            }
        }
        Some(("decrypt", sub_matches)) => {
            let input_file_path = sub_matches
                .get_one::<String>("input_file_path")
                .expect("String parses any input")
                .to_owned();
            let output_file_path = sub_matches
                .get_one::<String>("output_file_path")
                .expect("String parses any input")
                .to_owned();

            if let Some(pp) = passphrase {
                Operation::Decrypt(
                    pp,
                    InputFilePath(PathBuf::from(input_file_path)),
                    OutputFilePath(PathBuf::from(output_file_path)),
                )
            } else {
                bail!("Operation requires passphrase")
            }
        }

        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents `None`"),
    };
    Ok(Config {
        operation,
        verbosity,
    })
}
