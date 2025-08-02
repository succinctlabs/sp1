//! # SP1 SDK Utilities
//!
//! A collection of utilities for the SP1 SDK.

use std::{
    sync::Once,
    thread::{sleep, spawn},
    time::Duration,
};

use sp1_core_machine::io::SP1Stdin;
pub use sp1_core_machine::utils::setup_logger;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

static MEMORY_USAGE_MONITORING: Once = Once::new();

/// Spawns a thread that emits warnings when the used memory is high.
pub fn setup_memory_usage_monitoring() {
    MEMORY_USAGE_MONITORING.call_once(|| {
        spawn(|| {
            let mut sys = System::new_with_specifics(
                RefreshKind::new().with_memory(MemoryRefreshKind::new().with_ram()),
            );

            let total_memory = sys.total_memory();

            loop {
                sleep(Duration::from_secs(10));
                sys.refresh_memory();

                let used_memory = sys.used_memory();
                #[allow(clippy::cast_precision_loss)]
                let ratio = used_memory as f64 / total_memory as f64;

                if ratio > 0.8 {
                    tracing::warn!(
                        "Memory usage is high: {:.2}%, we recommend using the prover network",
                        ratio * 100.0
                    );
                }
            }
        });
    });
}

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
