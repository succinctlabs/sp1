use anyhow::Result;
use clap::Parser;
use curta_core::{
    utils::{self},
    CurtaProver, CurtaStdin,
};
use std::{
    env,
    fs::{self, File},
    io::Read,
    path::PathBuf,
    process::Command,
    str::FromStr,
};

use crate::CommandExecutor;

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
            let s = if s.starts_with("0x") {
                s.strip_prefix("0x").unwrap()
            } else {
                s
            };
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
}

impl ProveCmd {
    pub fn run(&self) -> Result<()> {
        let metadata_cmd = cargo_metadata::MetadataCommand::new();
        let metadata = metadata_cmd.exec().unwrap();
        let root_package = metadata.root_package();
        let root_package_name = root_package.as_ref().map(|p| &p.name);

        let build_target = "riscv32im-curta-zkvm-elf";
        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];

        Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "curta")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .args(["build", "--release", "--target", build_target, "--locked"])
            .run()
            .unwrap();

        let elf_path = metadata
            .target_directory
            .join(build_target)
            .join("release")
            .join(root_package_name.unwrap());
        let elf_dir = metadata.target_directory.parent().unwrap().join("elf");
        fs::create_dir_all(&elf_dir)?;
        fs::copy(&elf_path, elf_dir.join("riscv32im-curta-zkvm-elf"))?;

        if !self.profile {
            match env::var("RUST_LOG") {
                Ok(_) => {}
                Err(_) => env::set_var("RUST_LOG", "info"),
            }
            utils::setup_logger();
        } else {
            match env::var("RUST_TRACER") {
                Ok(_) => {}
                Err(_) => env::set_var("RUST_TRACER", "info"),
            }
            utils::setup_tracer();
        }

        let mut elf = Vec::new();
        File::open(elf_path.as_path().as_str())
            .expect("failed to open input file")
            .read_to_end(&mut elf)
            .expect("failed to read from input file");

        let mut stdin = CurtaStdin::new();
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
        let proof = CurtaProver::prove(&elf, stdin).unwrap();

        if let Some(ref path) = self.output {
            proof
                .save(path.to_str().unwrap())
                .expect("failed to save proof");
        }

        Ok(())
    }
}
