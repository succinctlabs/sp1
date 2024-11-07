use anyhow::Result;
use clap::{Args, Parser};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};
use yansi::Paint;

#[derive(Args)]
#[group(required = true, multiple = false)]
struct TemplateType {
    /// Use the `bare` template which includes just a program and script.
    #[arg(long)]
    bare: bool,

    /// Use the `evm` template which includes Solidity smart contracts for onchain integration.
    #[arg(long)]
    evm: bool,
}

#[derive(Parser)]
#[command(name = "new", about = "Setup a new project that runs inside the SP1.")]
pub struct NewCmd {
    /// The name of the project.
    name: String,

    /// The template to use for the project.
    #[command(flatten)]
    template: TemplateType,

    /// Version of sp1-project-template to use (branch or tag).
    #[arg(long, default_value = "main")]
    version: String,
}

const TEMPLATE_REPOSITORY_URL: &str = "https://github.com/succinctlabs/sp1-project-template";

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);

        // Create the root directory if it doesn't exist.
        if !root.exists() {
            fs::create_dir(&self.name)?;
        }

        println!("     \x1b[1m{}\x1b[0m {}", Paint::green("Cloning"), TEMPLATE_REPOSITORY_URL);

        // Clone the repository with the specified version.
        let mut command = Command::new("git");

        command
            .arg("clone")
            .arg("--branch")
            .arg(&self.version)
            .arg(TEMPLATE_REPOSITORY_URL)
            .arg(root.as_os_str())
            .arg("--depth=1");

        if self.template.evm {
            command.arg("--recurse-submodules").arg("--shallow-submodules");
        }

        // Stream output to stdout.
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        let output = command.output().expect("failed to execute command");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("failed to clone repository: {}", stderr));
        }

        // Remove the .git directory.
        fs::remove_dir_all(root.join(".git"))?;

        if self.template.evm {
            // Check if the user has `foundry` installed.
            if Command::new("foundry").arg("--version").output().is_err() {
                println!(
                "    \x1b[1m{}\x1b[0m Make sure to install Foundry to use contracts: https://book.getfoundry.sh/getting-started/installation",
                Paint::yellow("Warning:"),
            );
            }
        } else {
            // Remove the `contracts` directory.
            fs::remove_dir_all(root.join("contracts"))?;

            // Remove the `.gitmodules` file.
            fs::remove_file(root.join(".gitmodules"))?;
        }

        println!(
            " \x1b[1m{}\x1b[0m {} ({})",
            Paint::green("Initialized"),
            self.name,
            std::fs::canonicalize(root).expect("failed to canonicalize").to_str().unwrap()
        );

        Ok(())
    }
}
