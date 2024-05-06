use std::path::PathBuf;

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
