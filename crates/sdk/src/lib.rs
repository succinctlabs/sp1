//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

pub mod action;
pub mod artifacts;
pub mod install;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network-v2")]
#[path = "network-v2/mod.rs"]
pub mod network_v2;

use std::env;

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
pub use provers::SP1VerificationError;
use sp1_prover::components::DefaultProverComponents;

#[cfg(any(feature = "network", feature = "network-v2"))]
use {std::future::Future, tokio::task::block_in_place};

pub use provers::{CpuProver, MockProver, Prover};

pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
pub use sp1_core_machine::{io::SP1Stdin, riscv::cost::CostEstimator, SP1_CIRCUIT_VERSION};
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey,
};

#[cfg(any(feature = "network", feature = "network-v2"))]
use conflicting::conflicting;

/// A client for interacting with SP1.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

impl ProverClient {
    /// Creates a new [ProverClient].
    ///
    /// Setting the `SP1_PROVER` environment variable can change the prover used under the hood.
    /// - `local` (default): Uses [CpuProver] or [CudaProver] if the `cuda` feature is enabled.
    ///   Recommended for proving end-to-end locally.
    /// - `mock`: Uses [MockProver]. Recommended for testing and development.
    /// - `network`: Uses [NetworkProver]. Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// std::env::set_var("SP1_PROVER", "local");
    /// let client = ProverClient::new();
    /// ```
    #[deprecated = "Use `ProverClient::builder` instead"]
    pub fn new() -> Self {
        #[allow(unreachable_code)]
        match env::var("SP1_PROVER").unwrap_or("local".to_string()).to_lowercase().as_str() {
            "mock" => Self { prover: Box::new(MockProver::new()) },
            "local" => {
                #[cfg(debug_assertions)]
                eprintln!("Warning: Local prover in dev mode is not recommended. Proof generation may be slow.");
                Self {
                    #[cfg(not(feature = "cuda"))]
                    prover: Box::new(CpuProver::new()),
                    #[cfg(feature = "cuda")]
                    prover: Box::new(CudaProver::new(SP1Prover::new())),
                }
            }
            "network" => {
                let private_key = env::var("SP1_PRIVATE_KEY")
                    .expect("SP1_PRIVATE_KEY must be set for remote proving");
                let rpc_url = env::var("PROVER_NETWORK_RPC").ok();
                let skip_simulation =
                    env::var("SKIP_SIMULATION").map(|val| val == "true").unwrap_or_default();

                cfg_if! {
                    if #[cfg(feature = "network-v2")] {
                        Self {
                            prover: Box::new(NetworkProverV2::new(&private_key, rpc_url, skip_simulation)),
                        }
                    } else if #[cfg(feature = "network")] {
                        Self {
                            prover: Box::new(NetworkProverV1::new(&private_key, rpc_url, skip_simulation)),
                        }
                    } else {
                        panic!("network feature is not enabled")
                    }
                }
            }
            _ => panic!(
                "invalid value for SP1_PROVER environment variable: expected 'local', 'mock', or 'network'"
            ),
        }
    }

    /// Returns a [ProverClientBuilder] to easily create a [ProverClient].
    pub fn builder() -> ProverClientBuilder {
        ProverClientBuilder::default()
    }

    /// Creates a new [ProverClient] with the mock prover.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::mock();
    /// ```
    pub fn mock() -> Self {
        Self { prover: Box::new(MockProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the CPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::local();
    /// ```
    #[deprecated(note = "Please use `cpu` instead")]
    pub fn local() -> Self {
        Self { prover: Box::new(CpuProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the CPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::cpu();
    /// ```
    pub fn cpu() -> Self {
        Self { prover: Box::new(CpuProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the GPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::cuda();
    /// ```
    #[cfg(feature = "cuda")]
    pub fn cuda() -> Self {
        Self { prover: Box::new(CudaProver::new(SP1Prover::new())) }
    }

    /// Creates a new [ProverClient] with the network prover.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let private_key = std::env::var("SP1_PRIVATE_KEY").unwrap();
    /// let rpc_url = std::env::var("PROVER_NETWORK_RPC").ok();
    /// let skip_simulation =
    ///     std::env::var("SKIP_SIMULATION").map(|val| val == "true").unwrap_or_default();
    ///
    /// let client = ProverClient::network(private_key, rpc_url, skip_simulation);
    /// ```
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn network(private_key: String, rpc_url: Option<String>, skip_simulation: bool) -> Self {
        conflicting! {
            "network" => {
                Self {
                    prover: Box::new(NetworkProverV1::new(&private_key, rpc_url, skip_simulation)),
                }
            },
            "network-v2" => {
                Self {
                    prover: Box::new(NetworkProverV2::new(&private_key, rpc_url, skip_simulation)),
                }
            }
        }
    }

    /// Prepare to execute the given program on the given input (without generating a proof).
    /// The returned [action::Execute] may be configured via its methods before running.
    /// For example, calling [action::Execute::with_hook] registers hooks for execution.
    ///
    /// To execute, call [action::Execute::run], which returns
    /// the public values and execution report of the program after it has been executed.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Context, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let (public_values, report) = client.execute(elf, stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: SP1Stdin) -> action::Execute<'a> {
        action::Execute::new(self.prover.as_ref(), elf, stdin)
    }

    /// Prepare to prove the execution of the given program with the given input in the default
    /// mode. The returned [action::Prove] may be configured via its methods before running.
    /// For example, calling [action::Prove::compressed] sets the mode to compressed mode.
    ///
    /// To prove, call [action::Prove::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [action::Prove::compressed],
    /// [action::Prove::plonk], or [action::Prove::groth16] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Context, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> action::Prove<'a> {
        action::Prove::new(self.prover.as_ref(), pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Gets the current version of the SP1 zkVM.
    ///
    /// Note: This is not the same as the version of the SP1 SDK.
    pub fn version(&self) -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf);
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::cpu()
    }
}

/// Builder type for [`ProverClient`].
#[derive(Debug, Default)]
pub struct ProverClientBuilder {
    mode: Option<ProverMode>,
    #[cfg(any(feature = "network", feature = "network-v2"))]
    private_key: Option<String>,
    #[cfg(any(feature = "network", feature = "network-v2"))]
    rpc_url: Option<String>,
    #[cfg(any(feature = "network", feature = "network-v2"))]
    skip_simulation: bool,
}

impl ProverClientBuilder {
    /// Sets the mode of the prover client being created.
    pub fn mode(mut self, mode: ProverMode) -> Self {
        self.mode = Some(mode);
        self
    }

    ///  Sets the private key.
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL.
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Skips simulation.
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    /// Builds a [ProverClient], using the provided private key.
    pub fn build(self) -> ProverClient {
        match self.mode.expect("The prover mode is required") {
            ProverMode::Cpu => ProverClient::cpu(),
            #[cfg(feature = "cuda")]
            ProverMode::Cuda => {
                ProverClient::cuda()
            }
            #[cfg(any(feature = "network", feature = "network-v2"))]
            ProverMode::Network => {
                let private_key = self.private_key.expect("The private key is required");

                conflicting! {
                    "network" => {
                        ProverClient {
                            prover: Box::new(NetworkProverV1::new(&private_key, self.rpc_url, self.skip_simulation)),
                        }
                    },
                    "network-v2" => {
                        ProverClient {
                            prover: Box::new(NetworkProverV2::new(&private_key, self.rpc_url, self.skip_simulation)),
                        }
                    }
                }
            }
            ProverMode::Mock => ProverClient::mock(),
        }
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
