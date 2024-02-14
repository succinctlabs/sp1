use crate::CommandExecutor;
use anyhow::Result;
use cargo_metadata::camino::Utf8PathBuf;
use std::{fs, process::Command};

pub fn build_program() -> Result<Utf8PathBuf> {
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
    let result_elf_path = elf_dir.join("riscv32im-curta-zkvm-elf");
    fs::copy(elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}
