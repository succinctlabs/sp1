use anyhow::Result;
use clap::Parser;
#[derive(Parser)]
#[command(name = "build", about = "Build a Rust program into an ELF format")]
pub struct BuildCmd {
    #[clap(long)]
    target: Option<String>,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        let metadata_cmd = cargo_metadata::MetadataCommand::new();

        let metadata = metadata_cmd.exec().unwrap();

        println!("root {:?}", metadata.workspace_root);

        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("build");
        if let Some(target) = &self.target {
            cmd.arg(format!("--target={}", target));
        }

        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "link-arg=--fatal-warnings",
            "-C",
            "panic=abort",
        ];
        cmd.env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"));

        cmd.status()?;

        Ok(())
    }
}
