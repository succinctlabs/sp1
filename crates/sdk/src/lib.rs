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
pub mod cuda;
pub mod env;
pub mod install;
#[cfg(feature = "network")]
pub mod network;
pub mod utils;

// Re-export the client.
pub use crate::client::ProverClient;

// Re-export the provers.
pub use crate::{cpu::CpuProver, cuda::CudaProver, env::EnvProver};

#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;

// Re-export the proof and prover traits.
pub mod proof;
pub use proof::*;
pub mod prover;

pub use prover::{Prover, SP1VerificationError};

// Re-export the build utilities and executor primitives.
pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, Executor, HookEnv, SP1Context, SP1ContextBuilder};

// Re-export the machine/prover primitives.
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    HashableKey, ProverMode, SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};

// Re-export the utilities.
pub use utils::setup_logger;

#[cfg(test)]
mod tests {
    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, Prover, ProverClient, SP1Stdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, _) = client.execute(elf, &stdin).run().unwrap();
    }

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

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).cycle_limit(1).run().unwrap();
    }

    #[test]
    fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, &stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_io_override() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::HELLO_WORLD_ELF;

        let mut stdout = Vec::new();

        // Generate proof & verify.
        let stdin = SP1Stdin::new();
        let _ = client.execute(elf, &stdin).stdout(&mut stdout).run().unwrap();

        assert_eq!(stdout, b"Hello, world!\n");
    }

    #[test]
    fn test_e2e_compressed() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, &stdin).compressed().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_prove_plonk() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, &stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

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

    /// Show a warning if the `cuda` feature is enabled.
    #[allow(unused, deprecated)]
    fn show_cuda_warning() {
        cuda_is_deprecated();
    }
}
