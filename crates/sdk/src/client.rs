//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use crate::cpu::builder::CpuProverBuilder;
use crate::cuda::builder::CudaProverBuilder;
use crate::env::EnvProver;
use crate::network::builder::NetworkProverBuilder;

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
pub struct ProverClient;

impl ProverClient {
    /// Creates a new [`EnvProver`] from the environment.
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
    #[must_use]
    pub fn new() -> EnvProver {
        Self::from_env()
    }

    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// std::env::set_var("SP1_PROVER", "network");
    /// std::env::set_var("NETWORK_PRIVATE_KEY", "...");
    /// let prover = ProverClient::from_env();
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn from_env() -> EnvProver {
        EnvProver::new()
    }

    /// Creates a new [`ProverClientBuilder`] so that you can configure the prover client.
    #[must_use]
    pub fn builder() -> ProverClientBuilder {
        ProverClientBuilder
    }
}

/// A builder to define which proving client to use.
pub struct ProverClientBuilder;

impl ProverClientBuilder {
    /// Builds a [`CpuProver`] specifically for mock proving.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().mock().build();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn mock(&self) -> CpuProverBuilder {
        CpuProverBuilder { mock: true }
    }

    /// Builds a [`CpuProver`] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cpu().build();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn cpu(&self) -> CpuProverBuilder {
        CpuProverBuilder { mock: false }
    }

    /// Builds a [`CudaProver`] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn cuda(&self) -> CudaProverBuilder {
        CudaProverBuilder
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().network().build();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network(&self) -> NetworkProverBuilder {
        NetworkProverBuilder { private_key: None, rpc_url: None }
    }
}
