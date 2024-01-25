use std::env;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a Rust program")]
pub struct ProveCmd {
    #[clap(long)]
    target: Option<String>,

    #[clap(last = true)]
    cargo_args: Vec<String>,
}

impl ProveCmd {
    pub fn new() -> Self {
        Self {
            target: None,
            cargo_args: Vec::new(),
        }
    }

    pub fn run(&self) -> Result<()> {
        let metadata_cmd = cargo_metadata::MetadataCommand::new();

        let metadata = metadata_cmd.exec().unwrap();

        println!("root {:?}", metadata.workspace_root);

        let root_package = metadata.root_package();
        let root_package_name = root_package.as_ref().map(|p| &p.name);
        match root_package {
            Some(package) => {
                println!("root package {:?}", package);
            }
            None => {
                println!("no root package");
            }
        }

        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build");
        let mut build_target = env::var("CARGO_BUILD_TARGET").unwrap_or("".to_string());
        if let Some(target) = &self.target {
            cmd.arg(format!("--target={}", target));
            build_target = target.clone();
        }
        cmd.arg("--release");
        cmd.args(self.cargo_args.clone());

        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];
        cmd.env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"));

        let status = cmd.status()?;

        if status.success() {
            let elf_path = metadata
                .target_directory
                .join(build_target)
                .join("release")
                .join(root_package_name.unwrap());

            println!("elf path {:?}", elf_path);

            // curta_core::prover::runtime::tests::prove(curta_core::runtime::Program::from_elf(
            //     elf_path.as_str(),
            // ))
        }

        Ok(())
    }
}
impl Default for ProveCmd {
    fn default() -> Self {
        Self::new()
    }
}
