use std::path::PathBuf;

use anyhow::{Context, Result};

#[cfg(any(feature = "network", feature = "network-v2"))]
use {
    futures::StreamExt,
    indicatif::{ProgressBar, ProgressStyle},
    reqwest::Client,
    std::{cmp::min, fs::File, io::Write},
};

pub use sp1_prover::build::build_plonk_bn254_artifacts_with_dummy;

use crate::install::try_install_circuit_artifacts;

/// Exports the solidity verifier for PLONK proofs to the specified output directory.
///
/// WARNING: If you are on development mode, this function assumes that the PLONK artifacts have
/// already been built.
pub fn export_solidity_plonk_bn254_verifier(output_dir: impl Into<PathBuf>) -> Result<()> {
    let output_dir: PathBuf = output_dir.into();
    let artifacts_dir = if sp1_prover::build::sp1_dev_mode() {
        sp1_prover::build::plonk_bn254_artifacts_dev_dir()
    } else {
        try_install_circuit_artifacts("plonk")
    };
    let verifier_path = artifacts_dir.join("SP1VerifierPlonk.sol");

    if !verifier_path.exists() {
        return Err(anyhow::anyhow!("verifier file not found at {:?}", verifier_path));
    }

    std::fs::create_dir_all(&output_dir).context("Failed to create output directory.")?;
    let output_path = output_dir.join("SP1VerifierPlonk.sol");
    std::fs::copy(&verifier_path, &output_path).context("Failed to copy verifier file.")?;
    tracing::info!(
        "exported verifier from {} to {}",
        verifier_path.display(),
        output_path.display()
    );

    Ok(())
}

/// Exports the solidity verifier for Groth16 proofs to the specified output directory.
///
/// WARNING: If you are on development mode, this function assumes that the Groth16 artifacts have
/// already been built.
pub fn export_solidity_groth16_bn254_verifier(output_dir: impl Into<PathBuf>) -> Result<()> {
    let output_dir: PathBuf = output_dir.into();
    let artifacts_dir = if sp1_prover::build::sp1_dev_mode() {
        sp1_prover::build::groth16_bn254_artifacts_dev_dir()
    } else {
        try_install_circuit_artifacts("groth16")
    };
    let verifier_path = artifacts_dir.join("SP1VerifierGroth16.sol");

    if !verifier_path.exists() {
        return Err(anyhow::anyhow!("verifier file not found at {:?}", verifier_path));
    }

    std::fs::create_dir_all(&output_dir).context("Failed to create output directory.")?;
    let output_path = output_dir.join("SP1VerifierGroth16.sol");
    std::fs::copy(&verifier_path, &output_path).context("Failed to copy verifier file.")?;
    tracing::info!(
        "exported verifier from {} to {}",
        verifier_path.display(),
        output_path.display()
    );

    Ok(())
}

#[cfg(any(feature = "network", feature = "network-v2"))]
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut File,
) -> std::result::Result<(), String> {
    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", &url)))?;
    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));
    println!("Downloading {}", url);

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk).or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    let msg = format!("Downloaded {} to {:?}", url, file);
    pb.finish_with_message(msg);
    Ok(())
}
