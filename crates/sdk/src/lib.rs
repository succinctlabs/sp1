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

#[cfg(any(feature = "network", feature = "network-v2"))]
use {std::future::Future, tokio::task::block_in_place};

pub use provers::{LocalProver, Prover};

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
    pub fn new() -> EnvProver {
        Self::env()
    }

    pub fn builder() -> ProverClientBuilder {
        ProverClientBuilder::default()
    }

    /// Gets the current version of the SP1 zkVM.
    ///
    /// Note: This is not the same as the version of the SP1 SDK.
    pub fn version() -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }

    /// Builds a [EnvProver], filling in the mode and any unset fields with values from the env.
    pub fn env() -> EnvProver {
        EnvProver::new()
    }

    /// Builds a [LocalProver] specifically for local CPU proving.
    pub fn local() -> LocalProver {
        LocalProver::new(false)
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

    /// Builds a [LocalProver] specifically for mock proving.
    pub fn mock() -> LocalProver {
        LocalProver::new(true)
    }
}

/// Builder type for [`ProverClient`].
#[derive(Debug, Default)]
pub struct ProverClientBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
}

impl ProverClientBuilder {
    /// Sets the private key. Only used for network prover.
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL. Only used for network prover.
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
#[cfg(any(feature = "network", feature = "network-v2"))]
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

#[cfg(any(feature = "network", feature = "network-v2"))]
pub struct NetworkProverBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
}

#[cfg(any(feature = "network", feature = "network-v2"))]
impl NetworkProverBuilder {
    pub(crate) fn new() -> Self {
        Self { private_key: None, rpc_url: None }
    }

    /// Sets the private key. Only used for network prover.
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL. Only used for network prover.
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    pub fn build(self) -> NetworkProver {
        let private_key = self.private_key.unwrap_or_else(|| {
            env::var("SP1_PRIVATE_KEY").expect("Private key must be provided through `NetworkProverBuilder::private_key` or the SP1_PRIVATE_KEY environment variable.")
        });
        NetworkProver::new(&private_key, self.rpc_url)
    }
}

#[cfg(test)]
mod tests {

    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, CostEstimator, ProverClient, SP1Stdin};

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
