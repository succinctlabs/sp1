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
};

use crate::CommandExecutor;

#[derive(Parser)]
#[command(name = "prove", about = "Build and prove a program")]
pub struct ProveCmd {
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    input: Vec<u32>,

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

        let build_target = "riscv32im-succinct-zkvm-elf";
        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];

        Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .env("SUCCINCT_BUILD_IGNORE", "1")
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
        fs::copy(&elf_path, elf_dir.join("riscv32im-succinct-zkvm-elf"))?;

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
        for input in self.input.clone() {
            stdin.write(&input);
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
