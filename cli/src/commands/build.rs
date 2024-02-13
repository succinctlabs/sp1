use anyhow::Result;
use clap::Parser;
use std::{fs, process::Command};

use crate::CommandExecutor;

#[derive(Parser)]
#[command(name = "build", about = "(default) Build a program")]
pub struct BuildCmd {
    #[clap(long, action)]
    verbose: bool,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        let metadata_cmd = cargo_metadata::MetadataCommand::new();
        let metadata = metadata_cmd.exec().unwrap();
        let root_package = metadata.root_package();
        let root_package_name = root_package.as_ref().map(|p| &p.name);

        let build_target = "riscv32im-sp1-zkvm-elf";
        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];

        Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "sp1")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .env("SP1_BUILD_IGNORE", "1")
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
        fs::copy(elf_path, elf_dir.join("riscv32im-sp1-zkvm-elf"))?;

        Ok(())
    }
}
