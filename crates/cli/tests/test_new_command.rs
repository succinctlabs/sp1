#[cfg(test)]
mod test_new_command {
    use anyhow::Result;
    use sp1_cli::commands::new::{NewCmd, TemplateType};
    use std::{fs, path::PathBuf};
    use tempfile::tempdir;

    /// Helper that checks if a program (like git) is installed.
    /// Used to skip tests that require the program.
    fn is_program_in_path(program: &str) -> bool {
        std::process::Command::new(program).arg("--version").output().is_ok()
    }

    /// Test that running the bare template succeeds, creates the project directory,
    /// removes the `contracts` folder, and removes `.gitmodules` if present.
    /// This also checks that `.git` is removed after cloning.
    #[test]
    fn test_newcmd_bare_template() -> Result<()> {
        if !is_program_in_path("git") {
            eprintln!("Skipping test_newcmd_bare_template because `git` is not available.");
            return Ok(());
        }

        let temp = tempdir()?;
        let project_name = "test_bare_project";
        let project_path = temp.path().join(project_name);

        let cmd = NewCmd {
            name: project_path.to_string_lossy().to_string(),
            template: TemplateType { bare: true, evm: false },
            version: "main".to_string(),
        };

        // Run the command
        cmd.run()?;

        // Check the project directory exists
        assert!(project_path.exists());

        // Check the .git directory is removed
        assert!(!project_path.join(".git").exists());

        // The "contracts" folder should be removed for a bare template
        assert!(!project_path.join("contracts").exists());

        // .gitmodules file should also be removed if it existed
        assert!(!project_path.join(".gitmodules").exists());

        Ok(())
    }

    /// Test that running the evm template successfully clones and leaves the `contracts` folder in
    /// place.
    #[test]
    fn test_newcmd_evm_template() -> Result<()> {
        if !is_program_in_path("git") {
            eprintln!("Skipping test_newcmd_evm_template because `git` is not available.");
            return Ok(());
        }

        let temp = tempdir()?;
        let project_name = "test_evm_project";
        let project_path = temp.path().join(project_name);

        let cmd = NewCmd {
            name: project_path.to_string_lossy().to_string(),
            template: TemplateType { bare: false, evm: true },
            version: "main".to_string(),
        };

        cmd.run()?;

        // Check the project directory exists
        assert!(project_path.exists());

        // The "contracts" folder should be present for EVM template
        assert!(project_path.join("contracts").exists());

        // Ensure that .git was removed
        assert!(!project_path.join(".git").exists());

        Ok(())
    }

    /// Test that references to "alloy-sol" are removed from any Cargo.toml when using the bare
    /// template. This exercises the logic in `remove_alloy_sol_from_cargo_tomls`.
    #[test]
    fn test_remove_alloy_sol_from_cargo_tomls() -> Result<()> {
        if !is_program_in_path("git") {
            eprintln!(
                "Skipping test_remove_alloy_sol_from_cargo_tomls because `git` is not available."
            );
            return Ok(());
        }

        let temp = tempdir()?;
        let project_name = "test_bare_alloy_sol_removal";
        let project_path = temp.path().join(project_name);

        let cmd = NewCmd {
            name: project_path.to_string_lossy().to_string(),
            template: TemplateType { bare: true, evm: false },
            version: "main".to_string(),
        };

        cmd.run()?;

        // If test passes, we expect no references to "alloy-sol" in any Cargo.toml
        let cargo_toml_paths = find_cargo_toml_files(&project_path);
        for path in cargo_toml_paths {
            let contents = fs::read_to_string(&path)?;
            assert!(!contents.contains("alloy-sol"), "Found 'alloy-sol' reference in {:?}", path);
        }

        Ok(())
    }

    /// A simple helper to recursively find Cargo.toml files.
    fn find_cargo_toml_files(dir: &PathBuf) -> Vec<PathBuf> {
        let mut cargo_tomls = Vec::new();
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        cargo_tomls.extend(find_cargo_toml_files(&path));
                    } else if path.file_name().map_or(false, |p| p == "Cargo.toml") {
                        cargo_tomls.push(path);
                    }
                }
            }
        }
        cargo_tomls
    }
}
