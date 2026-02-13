//! # SP1 SDK Utilities
//!
//! A collection of utilities for the SP1 SDK.

use sp1_core_machine::io::SP1Stdin;
pub use sp1_core_machine::utils::setup_logger;
use sp1_prover_types::network_base_types::ProofMode;
use sp1_verifier::SP1ProofMode;

/// Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
pub(crate) fn sp1_dump(elf: &[u8], stdin: &SP1Stdin) {
    if std::env::var("SP1_DUMP").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        std::fs::write("program.bin", elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write("stdin.bin", stdin.clone()).unwrap();

        eprintln!("Dumped program.bin and stdin.bin.");
        // Exit with the success status.
        std::process::exit(0);
    }
}

pub(crate) fn proof_mode(mode: SP1ProofMode) -> ProofMode {
    match mode {
        SP1ProofMode::Core => ProofMode::Core,
        SP1ProofMode::Compressed => ProofMode::Compressed,
        SP1ProofMode::Groth16 => ProofMode::Groth16,
        SP1ProofMode::Plonk => ProofMode::Plonk,
    }
}

// Re-enable when the EnvProver is reimplemented.
// /// Check that SP1 SDK was built in release mode. Ensures that the prover and executor
// /// will be performant, which is important for benchmarking.
// pub(crate) fn check_release_build() {
//     #[cfg(debug_assertions)]
//     panic!("sp1-sdk must be built in release mode, please compile with the --release flag.");
// }
