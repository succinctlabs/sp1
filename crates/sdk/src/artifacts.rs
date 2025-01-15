//! # SP1 Artifacts
//!
//! A library for exporting the SP1 artifacts to the specified output directory.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::install::try_install_circuit_artifacts;
pub use sp1_prover::build::build_plonk_bn254_artifacts_with_dummy;

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
