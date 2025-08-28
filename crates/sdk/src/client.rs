//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use crate::{cpu::builder::CpuProverBuilder, cuda::builder::CudaProverBuilder, env::EnvProver};

#[cfg(feature = "network")]
use crate::network::{builder::NetworkProverBuilder, NetworkMode};

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
///
/// IMPORTANT: `ProverClient` only needs to be initialized ONCE and can be reused for subsequent
/// proving operations (can be shared across tasks by wrapping in an `Arc`). Note that the initial
/// initialization may be slow as it loads necessary proving parameters and sets up the environment.
pub struct ProverClient;

impl ProverClient {
    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
}

/// A builder to define which proving client to use.
pub struct ProverClientBuilder;

impl ProverClientBuilder {
    /// Builds a [`CpuProver`] specifically for mock proving.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
        CudaProverBuilder::default()
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network using default settings.
    ///
    /// Uses feature flag default (Reserved if reserved-capacity enabled, Mainnet otherwise).
    ///
    /// # Examples
    /// ```no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// // Use feature flag default
    /// let prover = ProverClient::builder().network().build();
    ///
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network(&self) -> NetworkProverBuilder {
        let network_mode = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "reserved-capacity")] {
                    NetworkMode::Reserved
                } else {
                    NetworkMode::Mainnet
                }
            }
        };

        NetworkProverBuilder {
            private_key: None,
            signer: None,
            rpc_url: None,
            tee_signers: None,
            network_mode: Some(network_mode),
        }
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network with a specified mode.
    ///
    /// # Examples
    /// ```no_run
    /// use sp1_sdk::{network::NetworkMode, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// // Explicitly specify network mode
    /// let prover = ProverClient::builder().network_for(NetworkMode::Mainnet).build();
    /// let prover = ProverClient::builder().network_for(NetworkMode::Reserved).build();
    ///
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network_for(&self, mode: NetworkMode) -> NetworkProverBuilder {
        NetworkProverBuilder {
            private_key: None,
            signer: None,
            rpc_url: None,
            tee_signers: None,
            network_mode: Some(mode),
        }
    }
}
