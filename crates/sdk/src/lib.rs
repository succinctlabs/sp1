//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

pub mod artifacts;
pub mod install;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network-v2")]
#[path = "network-v2/mod.rs"]
pub mod network_v2;
pub(crate) mod util;

#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver as NetworkProverV1;
#[cfg(feature = "network-v2")]
pub use crate::network_v2::proto::network::FulfillmentStrategy;
#[cfg(feature = "network-v2")]
pub use crate::network_v2::prover::NetworkProver as NetworkProverV2;
#[cfg(feature = "cuda")]
pub use crate::provers::CudaProver;

pub mod proof;
pub mod provers;
pub mod utils {
    pub use sp1_core_machine::utils::setup_logger;
}

use cfg_if::cfg_if;
pub use proof::*;
use provers::EnvProver;
pub use provers::SP1VerificationError;
use std::env;
pub use util::block_on;

#[cfg(any(feature = "network", feature = "network-v2"))]
pub use provers::{CpuProver, Prover};

pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
pub use sp1_core_machine::{io::SP1Stdin, riscv::cost::CostEstimator, SP1_CIRCUIT_VERSION};
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey,
};

/// A client for interacting with SP1.
pub struct ProverClient;

cfg_if! {
    if #[cfg(feature = "network-v2")] {
        type NetworkProver = NetworkProverV2;
    } else if #[cfg(feature = "network")] {
        type NetworkProver = NetworkProverV1;
    }
}

impl ProverClient {
    #[deprecated(since = "4.0.0", note = "use ProverClient::env() instead")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> EnvProver {
        Self::env()
    }

    /// Gets the current version of the SP1 zkVM.
    ///
    /// Note: This is not the same as the version of the SP1 SDK.
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
    /// let prover = ProverClient::env();
    /// let (pk, vk) = prover.setup(elf);
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    pub fn env() -> EnvProver {
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
        CpuProver::new(false)
    }

    /// Builds a [CudaProver] specifically for local NVIDIA GPU proving.
    #[cfg(feature = "cuda")]
    pub fn cuda() -> CudaProver {
        CudaProver::new(SP1Prover::new())
    }

    /// Builds a [NetworkProver] specifically for network proving.
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn network() -> NetworkProverBuilder {
        NetworkProverBuilder::new()
    }

    /// Builds a [CpuProver] specifically for mock proving.
    pub fn mock() -> CpuProver {
        CpuProver::new(true)
    }
}

/// A builder for [`NetworkProver`].
///
/// This builder is obtained via [`ProverClient::network()`] and allows setting
/// network-specific proving options like RPC URL and private key.
///
/// # Example
/// ```
/// let prover = ProverClient::network()
///     .private_key("my_private_key")
///     .build();
/// ```
#[cfg(any(feature = "network", feature = "network-v2"))]
pub struct NetworkProverBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
    #[cfg(feature = "network-v2")]
    strategy: FulfillmentStrategy,
}

#[cfg(any(feature = "network", feature = "network-v2"))]
impl NetworkProverBuilder {
    pub(crate) fn new() -> Self {
        Self {
            private_key: None,
            rpc_url: None,
            #[cfg(feature = "network-v2")]
            strategy: FulfillmentStrategy::Auction,
        }
    }

    /// Sets the private key.
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL.
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Sets the fulfillment strategy for the client. By default, the strategy is set to `Hosted`.
    #[cfg(feature = "network-v2")]
    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Builds a [NetworkProver].
    pub fn build(self) -> NetworkProver {
        let private_key = self.private_key.unwrap_or_else(|| {
            env::var("SP1_PRIVATE_KEY").expect("Private key must be provided through `NetworkProverBuilder::private_key` or the SP1_PRIVATE_KEY environment variable.")
        });
        NetworkProver::new(&private_key, self.rpc_url)
    }
}

#[cfg(test)]
mod tests {

    use crate::CostEstimator;
    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, Prover, ProverClient, SP1Stdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, report) = client.execute(elf, stdin).run().unwrap();
        tracing::info!("gas = {}", report.estimate_gas());
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).max_cycles(1).run().unwrap();
    }

    #[test]
    fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_compressed() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).compressed().run().unwrap();
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
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).plonk().run().unwrap();
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
        let client = ProverClient::mock();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}
