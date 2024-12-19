//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use sp1_prover::SP1_CIRCUIT_VERSION;

use crate::cpu::CpuProver;
use crate::cuda::CudaProver;
use crate::env::EnvProver;
use crate::network::builder::NetworkProverBuilder;

use sp1_prover::SP1Prover;

/// A client for interacting with the prover for the SP1 RISC-V zkVM.
///
/// The client can be used to execute programs, generate proofs, and verify proofs.
pub struct ProverClient;

impl ProverClient {
    /// Creates a new [EnvProver] from the environment.
    #[deprecated(since = "4.0.0", note = "use `ProverClient::from_env()` instead")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> EnvProver {
        Self::from_env()
    }

    /// Gets the current version of the SP1 RISC-V zkVM.
    ///
    /// WARNING: This is not the same as the version of the SP1 SDK.
    pub fn version() -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }

    /// Builds an [EnvProver], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// std::env::set_var("SP1_PROVER", "network");
    /// std::env::set_var("SP1_PRIVATE_KEY", "...");
    /// let prover = ProverClient::from_env();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    pub fn from_env() -> EnvProver {
        EnvProver::new()
    }

    /// Builds a [CpuProver] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::cpu();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    pub fn cpu() -> CpuProver {
        CpuProver::new()
    }

    /// Builds a [CudaProver] specifically for local NVIDIA GPU proving.
    pub fn cuda() -> CudaProver {
        CudaProver::new(SP1Prover::new())
    }

    /// Builds a [NetworkProver] specifically for network proving.
    #[cfg(feature = "network")]
    pub fn network() -> NetworkProverBuilder {
        NetworkProverBuilder { private_key: None, rpc_url: None }
    }

    /// Builds a [CpuProver] specifically for mock proving.
    pub fn mock() -> CpuProver {
        CpuProver::mock()
    }
}
