use anyhow::Context;
use std::process::Command;

// Checks that the succinct toolchain and native toolchain use the same rustc version
fn main() -> Result<(), anyhow::Error> {
    // TODO: Get compiler versions in sync. Then, enable this check
    // check_compiler_versions()?;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("`CARGO_MANIFEST_DIR` is always set by cargo during builds");
    let manifest_dir = std::path::Path::new(&manifest_dir);
    let program_dir = manifest_dir.parent().unwrap().join("program");

    let err = anyhow::anyhow!(
        "Failed to build the program located in `{}`.",
        program_dir.display(),
    );
    match execute_build_cmd(&program_dir) {
        Ok(status) => {
            if !status.success() {
                return Err(err).with_context(|| {
                    format!("Build process returned non-zero exit code {}", status)
                });
            }
        }
        Err(e) => return Err(err.context(e)),
    }
    Ok(())
}

/// Executes the `cargo prove build` command in the program directory
fn execute_build_cmd(
    program_dir: &impl AsRef<std::path::Path>,
) -> Result<std::process::ExitStatus, std::io::Error> {
    Command::new("cargo")
        .current_dir(program_dir)
        .args(&["prove", "build"])
        .spawn()? // Use .spawn().wait() instead of .output() so that the output is streamed to the console
        .wait()
}

/// Parses a string formatted like: "rustc 1.75.0-dev" into "1.75.0"
fn parse_version_string(string: &str) -> Result<String, anyhow::Error> {
    let version = string
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse version string"))?
        .split("-")
        .next()
        .unwrap();
    Ok(version.to_string())
}

/// Checks
fn check_compiler_versions() -> Result<(), anyhow::Error> {
    // Outputs a string formatted like: rustc 1.75.0-dev
    let succinct_cmd_output = Command::new("cargo")
        .env("RUSTUP_TOOLCHAIN", "succinct")
        .arg("version")
        .output()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    if !succinct_cmd_output.status.success() {
        anyhow::bail!("Failed to get succinct rustc version. Is succinct installed? If not you can install it with the `cargo-prove` tool. Try running `cargo prove install-toolchain`");
    }

    // Outputs a string formatted like: cargo 1.75.0
    let native_version_cmd = Command::new("cargo")
        .arg("version")
        .output()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    if !native_version_cmd.status.success() {
        anyhow::bail!("Failed to get native cargo version!");
    }

    let succinct_rustc_version =
        parse_version_string(&String::from_utf8_lossy(&succinct_cmd_output.stdout))?;
    let native_rustc_version =
        parse_version_string(&String::from_utf8_lossy(&native_version_cmd.stdout))?;

    if succinct_rustc_version != native_rustc_version {
        anyhow::bail!(
		 "succinct rustc version {} does not match native rustc version {}. Please update your succinct toolchain or use a rust-toolchain.toml file to force your native compiler to the correct version.",
		 succinct_rustc_version,
		 native_rustc_version
	 );
    }
    Ok(())
}
