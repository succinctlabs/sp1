use anyhow::Result;
use clap::Parser;
use std::{env, fs, process::Command};
use succinct_core::{
    runtime::{Program, Runtime},
    utils::{self, prove_core},
};

use crate::CommandExecutor;
use log::info;

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a Rust program")]
pub struct ProveCmd {
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    input: Vec<u32>,

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

        if self.verbose {
            info!(
                "running command: cargo build --release --target {}",
                build_target
            );
        }

        let args = vec!["build", "--release", "--target", build_target, "--locked"];

        Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .env("SUCCINCT_BUILD_IGNORE", "1")
            .args(args.clone())
            .run()
            .unwrap();

        if self.verbose {
            info!("running command: cargo {}", args.join(" "));
        }

        let elf_path = metadata
            .target_directory
            .join(build_target)
            .join("release")
            .join(root_package_name.unwrap());
        let elf_dir = metadata.target_directory.parent().unwrap().join("elf");
        if self.verbose {
            info!("copying elf to {:?}", elf_dir);
        }
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

        let program = Program::from_elf(elf_path.as_path().as_str());
        let mut runtime = Runtime::new(program);
        for input in self.input.clone() {
            runtime.write_stdin(&input);
        }
        runtime.run();
        prove_core(&mut runtime);

        Ok(())
    }
}
