pub use sp1_core::utils::setup_logger;
use sp1_core::SP1_CIRCUIT_VERSION;

/// Gets the current version of SP1 zkVM.
///
/// Note: this is not the same as the version of the SP1 SDK.
pub fn version() -> String {
    SP1_CIRCUIT_VERSION.to_string()
}
