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
pub struct ProverClient;

impl ProverClient {
    /// Creates a new [EnvProver] from the environment.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// std::env::set_var("SP1_PROVER", "network");
    /// std::env::set_var("NETWORK_PRIVATE_KEY", "...");
    /// std::env::set_var("NETWORK_RPC_URL", "...");
    /// let prover = ProverClient::from_env();
    /// ```
    #[deprecated(since = "4.0.0", note = "use `ProverClient::from_env()` instead")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> EnvProver {
        Self::from_env()
    }

    /// Gets the current version of the SP1 RISC-V zkVM.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let version = ProverClient::version();
    /// ```
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

    /// Builds a [CpuProver] specifically for mock proving.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::mock();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    pub fn mock() -> CpuProver {
        CpuProver::mock()
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

    /// Builds a [CudaProver] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::cuda();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    pub fn cuda() -> CudaProver {
        CudaProver::new(SP1Prover::new())
    }

    /// Builds a [NetworkProver] specifically for proving on the network.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::network().build();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[cfg(feature = "network")]
    pub fn network() -> NetworkProverBuilder {
        NetworkProverBuilder { private_key: None, rpc_url: None }
    }
}
