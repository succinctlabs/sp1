//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! This SDK provides a unified interface to deploy and verify proofs generated
//! by various provers (e.g. CPU, CUDA, ENV, and Network provers). It also re-exports
//! utilities for building SP1 executables and working with SP1 machines.
//!
//! ## Getting Started
//!
//! Visit the [Getting Started](https://docs.succinct.xyz/docs/sp1/getting-started/install)
//! section in the official SP1 documentation for a quick start guide.
//!
//! ## Example Usage
//!
//! ```rust
//! use sp1_sdk::{ProverClient, CpuProver, setup_logger};
//! 
//! fn main() {
//!     // Initialize logging
//!     setup_logger();
//!     
//!     // Build a prover client using the CPU prover
//!     let client = ProverClient::builder().cpu().build();
//!     
//!     // Load a sample ELF file (replace with actual artifact)
//!     let elf = test_artifacts::FIBONACCI_ELF;
//!     
//!     // Prepare input for the contract execution\n    let mut stdin = sp1_sdk::cpu::SP1Stdin::new();
//!     stdin.write(&10usize);
//!     
//!     // Execute the contract, generate a proof and verify it\n    let (proof, report) = client.execute(elf, &stdin).run().unwrap();
//!     assert!(report.success, \"Execution failed\");
//!     client.verify(&proof, &client.setup(elf).1).unwrap();
//! }
//! ```
//!
//! For more examples, please check the tests module.

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

/// Module containing the compiled artifacts of circuits.
pub mod artifacts;

/// Client module provides the API for interacting with the SP1 zkVM.
pub mod client;

/// CPU-based prover implementation.
pub mod cpu;

/// CUDA-based prover implementation.
pub mod cuda;

/// Environment-based prover implementation.
pub mod env;

/// Installation and setup helpers.
pub mod install;

#[cfg(feature = "network")]
/// Network-based prover implementation.
pub mod network;

/// Utility functions and helpers.
pub mod utils;

// Re-export the client.
pub use crate::client::ProverClient;

/// Re-export the provers.
pub use crate::cpu::CpuProver;
pub use crate::cuda::CudaProver;
pub use crate::env::EnvProver;
#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;

/// Re-export proof and prover traits.
///
/// # Examples
///
/// ```rust
/// use sp1_sdk::proof::*;\n\nfn verify_example() {\n    // Implement your proof verification logic here\n}\n```
pub mod proof;
pub use proof::*;

/// Re-export prover traits and error types.
pub mod prover;
pub use prover::{Prover, SP1VerificationError};

// Re-export build utilities and executor primitives.
pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, Executor, HookEnv, SP1Context, SP1ContextBuilder};

/// Re-export machine and prover primitives.
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    HashableKey, ProverMode, SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};

/// Re-export utilities.
pub use utils::setup_logger;

#[cfg(test)]
mod tests {
    use sp1_primitives::io::SP1PublicValues;
    use crate::{utils, Prover, ProverClient, SP1Stdin};

    /// Test executing the Fibonacci ELF.
    ///
    /// # Example
    ///
    /// ```rust
    /// let client = ProverClient::builder().cpu().build();
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let (report, _) = client.execute(elf, &stdin).run().unwrap();
    /// assert!(report.success);
    /// ```
    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, _) = client.execute(elf, &stdin).run().unwrap();
    }

    /// Test that executing a panic contract triggers a panic.
    ///
    /// # Example
    ///
    /// ```rust
    /// let client = ProverClient::builder().cpu().build();
    /// let elf = test_artifacts::PANIC_ELF;
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// client.execute(elf, &stdin).run().unwrap(); // Should panic\n
    /// ```
    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).run().unwrap();
    }

    /// Test that cycle limit failure causes a panic.
    #[test]
    #[should_panic]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).cycle_limit(1).run().unwrap();
    }

    /// End-to-end test: Generate proof and verify it.
    ///
    /// # Example
    ///
    /// ```rust
    /// let client = ProverClient::builder().cpu().build();
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let mut proof = client.prove(&pk, &stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// proof.public_values = SP1PublicValues::from(&[255, 4, 84]);\n
    /// if client.verify(&proof, &vk).is_ok() {\n    panic!(\"verified proof with invalid public values\")\n}\n
    /// ```\n
    #[test]
    fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let mut proof = client.prove(&pk, &stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    /// End-to-end test with compressed proof generation.
    #[test]
    fn test_e2e_compressed() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let mut proof = client.prove(&pk, &stdin).compressed().run().unwrap();
        client.verify(&proof, &vk).unwrap();
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    /// End-to-end test using Plonk proof generation.
    #[test]
    fn test_e2e_prove_plonk() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let mut proof = client.prove(&pk, &stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    /// End-to-end test using Plonk proof generation with a mocked prover.
    #[test]
    fn test_e2e_prove_plonk_mock() {
        utils::setup_logger();
        let client = ProverClient::builder().mock().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, &stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

#[cfg(all(feature = "cuda", not(sp1_ci_in_progress)))]
mod deprecated_check {
    #[deprecated(
        since = "4.0.0",
        note = "The `cuda` feature is deprecated, as the CudaProver is now supported by default."
    )]
    #[allow(unused)]
    fn cuda_is_deprecated() {}

    /// Displays a warning if the `cuda` feature is enabled.
    #[allow(deprecated, unused)]
    fn show_cuda_warning() {
        cuda_is_deprecated();
    }
}
