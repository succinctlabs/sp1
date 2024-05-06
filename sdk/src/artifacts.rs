use std::{cmp::min, fs::File, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;

pub const GROTH16_CIRCUIT_VERSION: u32 = 1;

pub const PLONK_BN254_CIRCUIT_VERSION: u32 = 1;

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

pub fn export_solidity_verifier(
    circuit_type: WrapCircuitType,
    output_dir: PathBuf,
    build_dir: Option<PathBuf>,
) -> Result<()> {
    let is_dev_mode = get_dev_mode();
    let build_dir = build_dir.unwrap_or_else(|| get_artifacts_dir(circuit_type, is_dev_mode));

    let verifier_name = match circuit_type {
        WrapCircuitType::Groth16 => "Groth16Verifier.sol",
        WrapCircuitType::Plonk => "PlonkVerifier.sol",
    };
    let verifier_path = build_dir.join(verifier_name);

    if !verifier_path.exists() {
        return Err(anyhow::anyhow!(
            "Verifier file not found at {:?}",
            verifier_path
        ));
    }

    std::fs::create_dir_all(&output_dir).context("Failed to create output directory.")?;

    let output_path = output_dir.join(verifier_name);

    std::fs::copy(&verifier_path, output_path).context("Failed to copy verifier file.")?;

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
