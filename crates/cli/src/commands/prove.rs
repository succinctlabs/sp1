use anstyle::*;
use anyhow::Result;
use clap::Parser;
use sp1_build::{execute_build_program, BuildArgs};
use sp1_core_machine::{
    io::SP1Stdin,
    utils::{setup_logger, setup_tracer},
};
use sp1_sdk::ProverClient;
use std::{env, fs::File, io::Read, path::PathBuf, str::FromStr, time::Instant};

use crate::util::{elapsed, write_status};

#[derive(Debug, Clone)]
enum Input {
    FilePath(PathBuf),
    HexBytes(Vec<u8>),
}

fn is_valid_hex_string(s: &str) -> bool {
    if s.len() % 2 != 0 {
        return false;
    }
    // All hex digits with optional 0x prefix
    s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
        || s.chars().all(|c| c.is_ascii_hexdigit())
}

impl FromStr for Input {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_valid_hex_string(s) {
            // Remove 0x prefix if present
            let s = if s.starts_with("0x") { s.strip_prefix("0x").unwrap() } else { s };
            if s.is_empty() {
                return Ok(Input::HexBytes(Vec::new()));
            }
            if !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("Invalid hex string.".to_string());
            }
            let bytes = hex::decode(s).map_err(|e| e.to_string())?;
            Ok(Input::HexBytes(bytes))
        } else if PathBuf::from(s).exists() {
            Ok(Input::FilePath(PathBuf::from(s)))
        } else {
            Err("Input must be a valid file path or hex string.".to_string())
        }
    }
}

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a program")]
pub struct ProveCmd {
    #[clap(long, value_parser)]
    input: Option<Input>,

    #[clap(long, action)]
    output: Option<PathBuf>,

    #[clap(long, action)]
    profile: bool,

    #[clap(long, action)]
    verbose: bool,

    #[clap(flatten)]
    build_args: BuildArgs,
}

impl ProveCmd {
    pub fn run(&self) -> Result<()> {
        let elf_paths = execute_build_program(&self.build_args, None)?;

        if !self.profile {
            match env::var("RUST_LOG") {
                Ok(_) => {}
                Err(_) => env::set_var("RUST_LOG", "info"),
            }
            setup_logger();
        } else {
            match env::var("RUST_TRACER") {
                Ok(_) => {}
                Err(_) => env::set_var("RUST_TRACER", "info"),
            }
            setup_tracer();
        }

        // The command predates multi-target build support. This allows the command to continue to
        // work when only one package is built, preserving backward compatibility.
        let elf_path = if elf_paths.len() == 1 {
            elf_paths[0].1.to_owned()
        } else {
            anyhow::bail!("the prove command does not work with multi-target builds");
        };

        let mut elf = Vec::new();
        File::open(elf_path.as_path().as_str())
            .expect("failed to open input file")
            .read_to_end(&mut elf)
            .expect("failed to read from input file");

        let mut stdin = SP1Stdin::new();
        if let Some(ref input) = self.input {
            match input {
                Input::FilePath(ref path) => {
                    let mut file = File::open(path).expect("failed to open input file");
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes)?;
                    stdin.write_slice(&bytes);
                }
                Input::HexBytes(ref bytes) => {
                    stdin.write_slice(bytes);
                }
            }
        }

        let start_time = Instant::now();
        let client = ProverClient::new();
        let (pk, _) = client.setup(&elf);
        let proof = client.prove(&pk, stdin).run().unwrap();

        if let Some(ref path) = self.output {
            proof.save(path.to_str().unwrap()).expect("failed to save proof");
        }

        let elapsed = elapsed(start_time.elapsed());
        let green = AnsiColor::Green.on_default().effects(Effects::BOLD);
        write_status(&green, "Finished", format!("proving in {}", elapsed).as_str());

        Ok(())
    }
}
