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

        // Stream output to stdout.
        command.stdout(Stdio::inherit()).stderr(Stdio::piped());

        let output = command.output().expect("failed to execute command");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to clone repository: {}", stderr));
        }

        // Remove the .git directory.
        fs::remove_dir_all(root.join(".git"))?;

        if self.template.evm {
            // Check if the user has `foundry` installed.
            if Command::new("forge").arg("--version").output().is_err() {
                println!(
                    "    \x1b[1m{}\x1b[0m Make sure to install Foundry and run `forge install` in the \"contracts\" folder to use contracts: https://book.getfoundry.sh/getting-started/installation",
                    Paint::yellow("Warning:"),
                );
            } else {
                println!(
                    "       \x1b[1m{}\x1b[0m Please run `forge install` in the \"contracts\" folder to setup contracts development",
                    Paint::blue("Info:"),
                );
            }
        } else if self.template.bare {
            // Remove the `contracts` directory.
            fs::remove_dir_all(root.join("contracts"))?;

            // Remove the `.gitmodules` file if it exists.
            let gitmodules_path = root.join(".gitmodules");
            if gitmodules_path.exists() {
                fs::remove_file(gitmodules_path)?;
            }

            // Remove the EVM-specific script (e.g., evm.rs).
            let evm_script_path = root.join("script").join("src").join("bin").join("evm.rs");
            if evm_script_path.exists() {
                fs::remove_file(evm_script_path)?;
            }

            // Recursively remove "alloy-sol" references from any Cargo.toml under the project root
            remove_alloy_sol_from_cargo_tomls(root)?;
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

/// Recursively walk through the project directory,
/// remove lines containing "alloy-sol" from any Cargo.toml files
fn remove_alloy_sol_from_cargo_tomls(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                remove_alloy_sol_from_cargo_tomls(&path)?;
            } else if path.file_name().map_or(false, |name| name == "Cargo.toml") {
                // Filter out lines containing "alloy-sol"
                let cargo_contents = fs::read_to_string(&path)?;
                let filtered_contents: String = cargo_contents
                    .lines()
                    .filter(|line| !line.contains("alloy-sol"))
                    .collect::<Vec<_>>()
                    .join("\n");
                fs::write(&path, filtered_contents)?;
            }
        }
    }
    Ok(())
}
