//! # SP1 SDK Utilities
//!
//! A collection of utilities for the SP1 SDK.

use std::{
    sync::Once,
    thread::{sleep, spawn},
    time::Duration,
};

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

/// The cycle limit and gas limit are determined according to the following priority:
///
/// 1. If either of the limits are explicitly set by the requester, use the specified value.
/// 2. If simulation is enabled, calculate the limits by simulating the execution of the program.
///    This is the default behavior.
/// 3. Otherwise, use the default limits ([`DEFAULT_CYCLE_LIMIT`] and [`DEFAULT_GAS_LIMIT`]).
#[cfg(feature = "network")]
pub(crate) fn get_execution_limits<C: SP1ProverComponents>(
    prover: &SP1Prover<C>,
    cycle_limit: Option<u64>,
    gas_limit: Option<u64>,
    elf: &[u8],
    stdin: &SP1Stdin,
    skip_simulation: bool,
) -> Result<(u64, u64, Option<Vec<u8>>)> {
    use crate::network::{Error, DEFAULT_CYCLE_LIMIT, DEFAULT_GAS_LIMIT};

    let cycle_limit_value = if let Some(cycles) = cycle_limit {
        cycles
    } else if skip_simulation {
        DEFAULT_CYCLE_LIMIT
    } else {
        // Will be calculated through simulation.
        0
    };

    let gas_limit_value = if let Some(gas) = gas_limit {
        gas
    } else if skip_simulation {
        DEFAULT_GAS_LIMIT
    } else {
        // Will be calculated through simulation.
        0
    };

    // If both limits were explicitly provided or skip_simulation is true, return immediately.
    if (cycle_limit.is_some() && gas_limit.is_some()) || skip_simulation {
        return Ok((cycle_limit_value, gas_limit_value, None));
    }

    // One of the limits were not provided and simulation is not skipped, so simulate to get one
    // or both limits
    let execute_result = prover
        .execute(elf, stdin, sp1_core_executor::SP1Context::builder().calculate_gas(true).build())
        .map_err(|_| Error::SimulationFailed)?;

    let (_, committed_value_digest, report) = execute_result;

    // Use simulated values for the ones that are not explicitly provided.
    let final_cycle_limit =
        if cycle_limit.is_none() { report.total_instruction_count() } else { cycle_limit_value };
    let final_gas_limit =
        if gas_limit.is_none() { report.gas.unwrap_or(DEFAULT_GAS_LIMIT) } else { gas_limit_value };

    let public_values_hash = Some(committed_value_digest.to_vec());

    Ok((final_cycle_limit, final_gas_limit, public_values_hash))
}
