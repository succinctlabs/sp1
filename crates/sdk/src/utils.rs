//! # SP1 SDK Utilities
//!
//! A collection of utilities for the SP1 SDK.

use sp1_core_machine::io::SP1Stdin;
pub use sp1_core_machine::utils::setup_logger;

/// Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
pub(crate) fn sp1_dump(elf: &[u8], stdin: &SP1Stdin) {
    if std::env::var("SP1_DUMP").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false) {
        std::fs::write("program.bin", elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write("stdin.bin", stdin.clone()).unwrap();

        eprintln!("Dumped program.bin and stdin.bin.");
        // Exit with the success status.
        std::process::exit(0);
    }
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
#[cfg(feature = "network")]
pub(crate) fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    use tokio::task::block_in_place;

    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

/// Check that SP1 SDK was built in release mode. Ensures that the prover and executor
/// will be performant, which is important for benchmarking.
pub(crate) fn check_release_build() {
    #[cfg(debug_assertions)]
    panic!("sp1-sdk must be built in release mode, please compile with the --release flag.");
}
