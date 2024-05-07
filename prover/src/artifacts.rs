use std::path::PathBuf;

use sp1_core::stark::{ShardProof, StarkVerifyingKey};

use crate::OuterSC;

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
pub fn get_groth16_artifacts_dir(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    wrapped_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    if groth16_dev_mode() {
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
        crate::build::groth16_artifacts(wrap_vk, wrapped_proof, build_dir.clone());
        build_dir
    } else if let Some(artifacts_dir) = groth16_artifacts_dir() {
        artifacts_dir
    } else {
        crate::install::groth16_artifacts();
        crate::install::groth16_artifacts_dir()
    }
}

/// Returns whether the `SP1_GROTH16_DEV_MODE` environment variable is enabled or disabled.
///
/// This variable controls whether a smaller version of the circuit will be used for generating the
/// Groth16 proofs. This is useful for development and testing purposes.
///
/// By default, the variable is enabled. It should be disabled for production use.
pub fn groth16_dev_mode() -> bool {
    let value = std::env::var("SP1_GROTH16_DEV_MODE").unwrap_or_else(|_| "true".to_string());
    value == "1" || value.to_lowercase() == "true"
}

/// Returns the path to the directory where the groth16 artifacts are stored.
///
/// This variable is useful for when you want to test the production circuit and have a local build
/// available for development purposes.
pub fn groth16_artifacts_dir() -> Option<PathBuf> {
    std::env::var("SP1_GROTH16_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .ok()
}
