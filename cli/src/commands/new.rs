use anyhow::Result;
use clap::Parser;
use std::{fs, path::Path, process::Command};
use yansi::Paint;

#[derive(Parser)]
#[command(name = "new", about = "Setup a new project that runs inside the SP1.")]
pub struct NewCmd {
    name: String,
}

const TEMPLATE_REPOSITORY_URL: &str = "https://github.com/succinctlabs/sp1-project-template";

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);

        // Create the root directory if it doesn't exist.
        if !root.exists() {
            fs::create_dir(&self.name)?;
        }

        // Clone the repository.
        let output = Command::new("git")
            .arg("clone")
            .arg(TEMPLATE_REPOSITORY_URL)
            .arg(root.as_os_str())
            .arg("--recurse-submodules")
            .arg("--depth=1")
            .output()
            .expect("failed to execute command");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("failed to clone repository: {}", stderr));
        }

        // Remove the .git directory.
        fs::remove_dir_all(root.join(".git"))?;

        // Check if the user has `foundry` installed.
        if Command::new("foundry").arg("--version").output().is_err() {
            println!(
                "    \x1b[1m{}\x1b[0m Make sure to install Foundry to use contracts: https://book.getfoundry.sh/getting-started/installation.",
                Paint::yellow("Warning:"),
            );
        }

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
