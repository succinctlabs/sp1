use std::process::Command;

use anyhow::Result;
use clap::Parser;

use crate::CommandExecutor;

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a Rust program")]
pub struct ProveCmd {
    #[clap(long)]
    target: Option<String>,

    #[clap(last = true)]
    cargo_args: Vec<String>,
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
            .args(["build", "--release", "--target", build_target])
            .run()?;

        let elf_path = metadata
            .target_directory
            .join(build_target)
            .join("release")
            .join(root_package_name.unwrap());
        println!("Successfully built ELF at {:?}", elf_path);

        Ok(())
    }
}
