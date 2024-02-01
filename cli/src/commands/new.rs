use anyhow::Result;
use clap::Parser;
use std::{fs, path::Path};

const CARGO_TOML: &str = include_str!("../assets/Cargo.toml");
const MAIN_RS: &str = include_str!("../assets/main.rs");

#[derive(Parser)]
#[command(name = "new", about = "Setup a new zkVM cargo project.")]
pub struct NewCmd {
    name: String,
}

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        fs::create_dir(&self.name)?;

        let root = Path::new(&self.name);
        let cargo_toml_path = root.join("Cargo.toml");
        let src_dir = root.join("src");
        let main_path = src_dir.join("main.rs");
        let elf_path = root.join("elf");
        let elf_binary_path = elf_path.join("riscv32im-succinct-zkvm-elf");

        fs::create_dir(&src_dir)?;
        fs::create_dir(&elf_path)?;

        fs::write(cargo_toml_path, CARGO_TOML.replace("unnamed", &self.name))?;
        fs::write(main_path, MAIN_RS)?;
        fs::write(elf_binary_path, "")?;

        Ok(())
    }
}
