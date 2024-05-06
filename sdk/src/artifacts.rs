use std::path::PathBuf;

use anyhow::{Context, Result};
use sp1_core::stark::{ShardProof, StarkVerifyingKey};
use sp1_prover::{build::dummy_proof, OuterSC};

use crate::provers::utils;

/// Exports the soliditiy verifier for Groth16 proofs to the specified output directory.
///
/// WARNING: This function may take some time to complete if `SP1_DEV_WRAPPER` is enabled (which
/// is the default) as it needs to generate an end-to-end dummy proof to export the verifier.
pub fn export_solidity_groth16_verifier(output_dir: impl Into<PathBuf>) -> Result<()> {
    let output_dir: PathBuf = output_dir.into();
    let (wrap_vk, wrapped_proof) = dummy_proof();
    let artifacts_dir = get_groth16_artifacts_dir(&wrap_vk, &wrapped_proof);
    let verifier_path = artifacts_dir.join("Groth16Verifier.sol");

    if !verifier_path.exists() {
        return Err(anyhow::anyhow!(
            "verifier file not found at {:?}",
            verifier_path
        ));
    }

    std::fs::create_dir_all(&output_dir).context("Failed to create output directory.")?;
    let output_path = output_dir.join("Groth16Verifier.sol");
    std::fs::copy(&verifier_path, output_path).context("Failed to copy verifier file.")?;

    Ok(())
}

/// Gets the artifacts directory for Groth16 based on the current environment variables.
///
/// - If `SP1_GROTH16_DEV_MODE` is enabled, we will compile a smaller version of the final
/// circuit and rebuild it for every proof. This is useful for development and testing purposes, as
/// it allows us to test the end-to-end proving without having to wait for the circuit to compile or
/// download.
///
/// - If `SP1_GROTH16_ARTIFACTS_DIR` is set, we will use the artifacts from that directory. This is
/// useful for when you want to test the production circuit and have a local build available for
/// development purposes.
///
/// - Otherwise, assume this is an official release and download the artifacts from the official
/// download url.
pub(crate) fn get_groth16_artifacts_dir(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    wrapped_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    if utils::groth16_dev_mode() {
        tracing::debug!("proving groth16 inside development mode");
        let build_dir = tempfile::tempdir()
            .expect("failed to create temporary directory")
            .into_path();
        if let Err(err) = std::fs::create_dir_all(&build_dir) {
            panic!(
                "failed to create build directory for groth16 artifacts: {}",
                err
            );
        }
        sp1_prover::build::groth16_artifacts(wrap_vk, wrapped_proof, build_dir.clone());
        build_dir
    } else if let Some(artifacts_dir) = utils::groth16_artifacts_dir() {
        artifacts_dir
    } else {
        sp1_prover::install::groth16_artifacts();
        sp1_prover::install::groth16_artifacts_dir()
    }
}
