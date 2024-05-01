use std::{cmp::min, fs::File, io::Write, path::PathBuf, process::Command};

use anyhow::{Context, Result};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use sp1_prover::build::{build_groth16_artifacts, build_plonk_artifacts};

pub const GROTH16_CIRCUIT_VERSION: &str = "nightly";
pub const PLONK_BN254_CIRCUIT_VERSION: &str = "nightly";

#[derive(Clone, Debug, Copy)]
pub enum WrapCircuitType {
    Groth16,
    Plonk,
}

impl std::fmt::Display for WrapCircuitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapCircuitType::Groth16 => write!(f, "groth16"),
            WrapCircuitType::Plonk => write!(f, "plonk"),
        }
    }
}

const CIRCUIT_ARTIFACTS_URL: &str = "https://github.com/succinctlabs/sp1/releases/download/";

/// Returns the directory where the circuit artifacts are stored. If SP1_CIRCUIT_DIR is set, it
/// returns that directory. Otherwise, it returns ~/.sp1/circuits/<type>/<version>.
pub fn get_artifacts_dir(circuit_type: WrapCircuitType, is_dev_mode: bool) -> PathBuf {
    let env_var = std::env::var("SP1_CIRCUIT_DIR");

    let dev_suffix = if is_dev_mode { "_dev" } else { "" };

    env_var.map(PathBuf::from).unwrap_or_else(|_| {
        dirs::home_dir()
            .expect("Failed to get home directory.")
            .join(".sp1")
            .join("circuits")
            .join(match circuit_type {
                WrapCircuitType::Groth16 => {
                    format!("{}{}/{}", circuit_type, dev_suffix, GROTH16_CIRCUIT_VERSION)
                }
                WrapCircuitType::Plonk => {
                    format!(
                        "{}{}/{}",
                        circuit_type, dev_suffix, PLONK_BN254_CIRCUIT_VERSION
                    )
                }
            })
    })
}

pub fn get_dev_mode() -> bool {
    std::env::var("SP1_DEV_WRAPPER")
        .unwrap_or("true".to_string())
        .to_lowercase()
        == "true"
}

/// Installs the prebuilt artifacts for the given circuit type.
///
/// If build_dir is not provided, the artifacts are installed in ~/.sp1/circuits/<type>/<version>.
/// If version is not provided, the latest version is installed.
pub fn install_circuit_artifacts(
    circuit_type: WrapCircuitType,
    overwrite_existing: bool,
    build_dir: Option<PathBuf>,
    version: Option<&str>,
) -> Result<()> {
    let build_dir = build_dir.unwrap_or_else(|| get_artifacts_dir(circuit_type, false));

    if build_dir.exists() {
        // If dir exists and not overwrite_existing, just return.
        if !overwrite_existing {
            return Ok(());
        }
        // Otherwise we will overwrite, so delete existing directory.
        std::fs::remove_dir_all(&build_dir)
            .context("Failed to remove existing build directory.")?;
    }

    println!(
        "Building {:?} artifacts in {}",
        circuit_type,
        build_dir.display()
    );

    // Mkdir
    std::fs::create_dir_all(&build_dir).context("Failed to create build directory.")?;

    // Download to a temporary file.
    let version_str = version.unwrap_or(match circuit_type {
        WrapCircuitType::Groth16 => GROTH16_CIRCUIT_VERSION,
        WrapCircuitType::Plonk => PLONK_BN254_CIRCUIT_VERSION,
    });
    let temp_dir = tempfile::tempdir()?;
    let temp_file_path = temp_dir.path().join(format!("{}.tar.gz", circuit_type));

    // Remove file if it exists
    if temp_file_path.exists() {
        std::fs::remove_file(&temp_file_path)?;
    }
    let mut temp_file = File::create(&temp_file_path)?;
    let filename = format!("{}.tar.gz", circuit_type);
    let download_url = format!("{}{}/{}", CIRCUIT_ARTIFACTS_URL, version_str, filename);

    let rt = tokio::runtime::Runtime::new()?;
    let client = Client::builder().build()?;
    rt.block_on(download_file(&client, &download_url, &mut temp_file))
        .unwrap();

    // Extract the tarball to the build directory.
    Command::new("ls")
        .current_dir(&temp_dir)
        .spawn()
        .with_context(|| "while executing ls")?
        .wait()
        .with_context(|| "while waiting for ls")?;

    let mut res = Command::new("tar")
        .current_dir(&temp_dir)
        .args([
            "-Pxzf",
            temp_file_path.to_str().unwrap(),
            "-C",
            build_dir.to_str().unwrap(),
        ])
        .spawn()
        .with_context(|| "while executing tar")?;

    res.wait()?;

    temp_dir.close()?;

    Ok(())
}

pub fn build_circuit_artifacts(
    circuit_type: WrapCircuitType,
    overwrite_existing: bool,
    build_dir: Option<PathBuf>,
) -> Result<()> {
    let is_dev_mode = get_dev_mode();
    let build_dir = build_dir.unwrap_or_else(|| get_artifacts_dir(circuit_type, is_dev_mode));

    if build_dir.exists() {
        if !overwrite_existing {
            // If dir exists, just return.
            return Ok(());
        }
        // Otherwise we will overwrite, so delete existing directory.
        std::fs::remove_dir_all(&build_dir)
            .context("Failed to remove existing build directory.")?;
    }

    println!(
        "Building {:?} artifacts in {}",
        circuit_type,
        build_dir.display()
    );

    // Mkdir
    std::fs::create_dir_all(&build_dir).context("Failed to create build directory.")?;

    // Write version file.
    let version_file = build_dir.join("VERSION");
    let mut version_file = File::create(version_file)?;
    let version_str = match circuit_type {
        WrapCircuitType::Groth16 => GROTH16_CIRCUIT_VERSION,
        WrapCircuitType::Plonk => PLONK_BN254_CIRCUIT_VERSION,
    };
    version_file.write_all(
        format!(
            "sp1 {} circuit {}{} {}",
            env!("VERGEN_GIT_SHA"),
            circuit_type,
            if is_dev_mode { "_dev" } else { "" },
            version_str,
        )
        .as_bytes(),
    )?;

    match circuit_type {
        WrapCircuitType::Groth16 => build_groth16_artifacts(build_dir),
        WrapCircuitType::Plonk => build_plonk_artifacts(build_dir),
    };

    Ok(())
}

pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut File,
) -> std::result::Result<(), String> {
    let res = client
        .get(url)
        .send()
        .await
        .or(Err(format!("Failed to GET from '{}'", &url)))?;
    let total_size = res
        .content_length()
        .ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));
    println!("Downloading {}", url);

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk)
            .or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    let msg = format!("Downloaded {} to {:?}", url, file);
    pb.finish_with_message(msg);
    Ok(())
}
