use anyhow::Result;
use clap::Parser;
use std::{fs, path::Path};
use yansi::Paint;

const PROGRAM_CARGO_TOML: &str = include_str!("../assets/program/Cargo.toml");
const PROGRAM_MAIN_RS: &str = include_str!("../assets/program/main.rs");
const SCRIPT_CARGO_TOML: &str = include_str!("../assets/script/Cargo.toml");
const SCRIPT_MAIN_RS: &str = include_str!("../assets/script/main.rs");
const SCRIPT_RUST_TOOLCHAIN: &str = include_str!("../assets/script/rust-toolchain");
const GIT_IGNORE: &str = include_str!("../assets/.gitignore");

#[derive(Parser)]
#[command(name = "new", about = "Setup a new project that runs inside the SP1.")]
pub struct NewCmd {
    name: String,
}

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);
        let program_root = root.join("program");
        let script_root = root.join("script");

        // Create the root directory.
        fs::create_dir(&self.name)?;

        // Create the program directory.
        fs::create_dir(&program_root)?;
        fs::create_dir(program_root.join("src"))?;
        fs::create_dir(program_root.join("elf"))?;
        fs::write(
            program_root.join("Cargo.toml"),
            PROGRAM_CARGO_TOML.replace("unnamed", &self.name),
        )?;
        fs::write(program_root.join("src").join("main.rs"), PROGRAM_MAIN_RS)?;

        // Create the runner directory.
        fs::create_dir(&script_root)?;
        fs::create_dir(script_root.join("src"))?;
        fs::write(
            script_root.join("Cargo.toml"),
            SCRIPT_CARGO_TOML.replace("unnamed", &self.name),
        )?;
        fs::write(script_root.join("src").join("main.rs"), SCRIPT_MAIN_RS)?;
        fs::write(script_root.join("rust-toolchain"), SCRIPT_RUST_TOOLCHAIN)?;

        // Add .gitignore file to root.
        fs::write(root.join(".gitignore"), GIT_IGNORE)?;

        println!(
            "    \x1b[1m{}\x1b[0m {} ({})",
            Paint::green("Initialized"),
            self.name,
            std::fs::canonicalize(root)
                .expect("failed to canonicalize")
                .to_str()
                .unwrap()
        );

        Ok(())
    }
}
