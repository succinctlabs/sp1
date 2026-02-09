//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use crate::{
    cpu::builder::CpuProverBuilder, cuda::builder::CudaProverBuilder, env::EnvProver,
    light::builder::LightProverBuilder, mock::builder::MockProverBuilder,
};

#[cfg(feature = "network")]
use crate::network::{builder::NetworkProverBuilder, NetworkMode};

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
///
/// IMPORTANT: `ProverClient` only needs to be initialized ONCE and can be reused for subsequent
/// proving operations, all provers types are cheap to clone and share across threads.
///
/// Note that the initialization may be slow as it loads necessary proving parameters and sets up
/// the environment.
pub struct ProverClient;

impl ProverClient {
    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     std::env::set_var("SP1_PROVER", "network");
    ///     std::env::set_var("NETWORK_PRIVATE_KEY", "...");
    ///     let prover = ProverClient::from_env().await;
    ///
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub async fn from_env() -> EnvProver {
        EnvProver::new().await
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
    /// Builds a [`CpuProver`] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().cpu().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn cpu(&self) -> CpuProverBuilder {
        CpuProverBuilder::new()
    }

    /// Builds a [`CudaProver`] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().cuda().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn cuda(&self) -> CudaProverBuilder {
        CudaProverBuilder::default()
    }

    /// Builds a [`MockProver`] for testing without real proving or verification.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().mock().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn mock(&self) -> MockProverBuilder {
        MockProverBuilder::new()
    }

    /// Builds a [`LightProver`] that only executes and verifies but does not generate proofs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().light().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn light(&self) -> LightProverBuilder {
        LightProverBuilder::new()
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().network().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network(&self) -> NetworkProverBuilder {
        NetworkProverBuilder::new()
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network with a specified mode.
    ///
    /// # Examples
    /// ```no_run
    /// use sp1_sdk::{network::NetworkMode, Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
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
