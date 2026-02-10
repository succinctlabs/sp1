//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://docs.succinct.xyz/docs/sp1/getting-started/install) section
//! in the official SP1 documentation for a quick start guide.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![warn(missing_docs)]

pub mod artifacts;
pub mod client;
pub mod cpu;
pub use cpu::CpuProver;
pub mod mock;
pub use mock::MockProver;
pub mod light;
pub use light::LightProver;
pub mod cuda;
pub use cuda::CudaProver;
pub mod env;

pub mod install;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network")]
pub use network::prover::NetworkProver;

#[cfg(feature = "blocking")]
pub mod blocking;

pub mod utils;

// Re-export the client.
pub use crate::client::ProverClient;

// Re-export the proof and prover traits.
pub mod proof;
pub use proof::*;
pub mod prover;

/// The traits that define how to interact with the prover.
pub use prover::{ProveRequest, Prover, ProvingKey, SP1ProvingKey, SP1VerificationError};

// Re-export the build utilities and executor primitives.
pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder, StatusCode};

// Re-export the machine/prover primitives.
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::{io::SP1PublicValues, Elf};
pub use sp1_prover::{HashableKey, ProverMode, SP1VerifyingKey, SP1_CIRCUIT_VERSION};

/// A prelude, including all the types and traits that are commonly used.
pub mod prelude {
    pub use super::{
        include_elf, Elf, HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofWithPublicValues,
        SP1Stdin,
    };
}

// Re-export the utilities.
pub use utils::setup_logger;

#[cfg(all(test, feature = "slow-tests"))]
mod tests {
    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, MockProver, Prover, ProverClient, SP1Stdin};

    #[tokio::test]
    async fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_pv, report) = client.execute(elf, stdin).await.unwrap();

        assert_eq!(report.exit_code, 0);
    }

    #[tokio::test]
    async fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, report) = client.execute(elf, stdin).await.unwrap();
        assert_eq!(report.exit_code, 1);
    }

    // TODO: reimplement the cycle limit logic and revive this test.
    #[should_panic]
    #[tokio::test]
    #[ignore = "The cycle limit logic needs to be reimplemented."]
    async fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).cycle_limit(1).await.unwrap();
    }

    /// Test that cycle tracking via `client.execute()` populates the `ExecutionReport`.
    ///
    /// The cycle-tracker test program uses:
    /// - `cycle-tracker-report-start/end: h` - should populate `cycle_tracker` `HashMap`
    /// - `cycle-tracker-report-start/end: repeated` (3x) - should accumulate cycles
    #[tokio::test]
    async fn test_cycle_tracker_report_variants() {
        utils::setup_logger();
        let client = MockProver::new().await;
        let elf = test_artifacts::CYCLE_TRACKER_ELF;
        let stdin = SP1Stdin::new();

        let (_pv, report) = client.execute(elf, stdin).await.unwrap();

        // Verify cycle tracking for report variants
        // "h" should have been tracked once
        assert!(
            report.cycle_tracker.contains_key("h"),
            "Expected cycle_tracker to contain 'h', got: {:?}",
            report.cycle_tracker
        );
        let h_cycles = *report.cycle_tracker.get("h").unwrap();
        assert!(h_cycles > 0, "Expected 'h' to have positive cycles, got: {h_cycles}");

        // "repeated" should have been tracked 3 times
        assert!(
            report.cycle_tracker.contains_key("repeated"),
            "Expected cycle_tracker to contain 'repeated', got: {:?}",
            report.cycle_tracker
        );
        let repeated_cycles =
            *report.cycle_tracker.get("repeated").expect("repeated should be populated");
        assert!(
            repeated_cycles > 0,
            "Expected 'repeated' to have positive cycles, got: {repeated_cycles}"
        );

        // Verify invocation tracker for repeated label
        assert!(
            report.invocation_tracker.contains_key("repeated"),
            "Expected invocation_tracker to contain 'repeated', got: {:?}",
            report.invocation_tracker
        );
        let repeated_invocations =
            *report.invocation_tracker.get("repeated").expect("repeated should be populated");
        assert_eq!(
            repeated_invocations, 3,
            "Expected 'repeated' to have 3 invocations, got: {repeated_invocations}"
        );

        // Non-report variants (f, g) should NOT be in the report
        // (they use cycle-tracker-start/end without "report")
        assert!(
            !report.cycle_tracker.contains_key("f"),
            "Expected cycle_tracker to NOT contain 'f' (non-report variant)"
        );
        assert!(
            !report.cycle_tracker.contains_key("g"),
            "Expected cycle_tracker to NOT contain 'g' (non-report variant)"
        );

        tracing::info!("report: {}", report);
    }

    /// Test that cycle tracking works with the derive macro (non-report variant).
    /// The macro uses eprintln which goes to stderr (fd=2).
    /// Non-report variants should be parsed but NOT populate the report.
    #[tokio::test]
    async fn test_cycle_tracker_macro_non_report() {
        utils::setup_logger();
        let client = MockProver::new().await;
        let elf = test_artifacts::CYCLE_TRACKER_ELF;
        let stdin = SP1Stdin::new();

        let (_pv, report) = client.execute(elf, stdin).await.unwrap();

        // The macro uses non-report variant, so "f" should NOT be in cycle_tracker
        assert!(
            !report.cycle_tracker.contains_key("f"),
            "Non-report variant 'f' should not be in cycle_tracker"
        );
    }

    /// Test that cycle tracking works correctly across chunk boundaries.
    #[tokio::test]
    async fn test_cycle_tracker_across_chunks() {
        use sp1_core_executor::SP1CoreOpts;

        utils::setup_logger();

        // Use a small chunk threshold to force multiple chunks
        let mut opts = SP1CoreOpts::default();
        opts.minimal_trace_chunk_threshold = 1000;

        let client = MockProver::new_with_opts(opts).await;
        let elf = test_artifacts::CYCLE_TRACKER_ELF;
        let stdin = SP1Stdin::new();

        // Enable calculate_gas to use the chunk threshold
        let (_pv, report) = client.execute(elf, stdin).calculate_gas(true).await.unwrap();

        // Verify cycle tracking works correctly across chunks
        assert!(report.cycle_tracker.contains_key("h"));
        assert!(*report.cycle_tracker.get("h").unwrap() > 0);

        assert!(report.cycle_tracker.contains_key("repeated"));
        assert!(*report.cycle_tracker.get("repeated").unwrap() > 0);

        assert_eq!(*report.invocation_tracker.get("repeated").unwrap_or(&0), 3);
    }

    #[tokio::test]
    async fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).await.unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[tokio::test]
    async fn test_e2e_core_panic() {
        use sp1_core_executor::StatusCode;

        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new().await;
        let elf = test_artifacts::PANIC_ELF;
        let pk = client.setup(elf).await.unwrap();
        let stdin = SP1Stdin::new();

        // Generate proof & verify.
        let proof = client.prove(&pk, stdin).core().await.unwrap();
        client.verify(&proof, &pk.vk, StatusCode::new(1)).unwrap();

        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid exit code")
        }

        if client.verify(&proof, &pk.vk, StatusCode::new(0)).is_ok() {
            panic!("verified proof with invalid exit code")
        }
    }

    // TODO: reimplement the custom stdout/stderr and revive this test
    // #[tokio::test]
    // async fn test_e2e_io_override() {
    //     utils::setup_logger();
    //     let client = ProverClient::builder().cpu().build().await;
    //     let elf = test_artifacts::HELLO_WORLD_ELF;

    //     let mut stdout = Vec::new();

    //     // Generate proof & verify.
    //     let stdin = SP1Stdin::new();
    //     let _ = client.execute(elf, stdin).stdout(&mut stdout).run().unwrap();

    //     assert_eq!(stdout, b"Hello, world!\n");
    // }

    #[tokio::test]
    async fn test_e2e_compressed() {
        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).compressed().await.unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[tokio::test]
    async fn test_e2e_compressed_panic() {
        use sp1_core_executor::StatusCode;

        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new().await;
        let elf = test_artifacts::PANIC_ELF;
        let pk = client.setup(elf).await.unwrap();
        let stdin = SP1Stdin::new();

        // Generate proof & verify.
        let proof = client.prove(&pk, stdin).compressed().await.unwrap();
        client.verify(&proof, &pk.vk, StatusCode::new(1)).unwrap();

        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid exit code")
        }

        if client.verify(&proof, &pk.vk, StatusCode::new(0)).is_ok() {
            panic!("verified proof with invalid exit code")
        }
    }

    #[tokio::test]
    async fn test_e2e_plonk() {
        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new().await;
        let pk = client.setup(test_artifacts::FIBONACCI_ELF).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        let proof = client.prove(&pk, stdin).plonk().await.unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();
    }

    #[tokio::test]
    async fn test_e2e_groth16() {
        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        let proof = client.prove(&pk, stdin).groth16().await.unwrap();

        client.verify(&proof, &pk.vk, None).unwrap();
    }
}
