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

use anyhow::Result;
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

/// A client for interacting with SP1.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

cfg_if! {
    if #[cfg(feature = "network-v2")] {
        type NetworkProver = NetworkProverV2;
    } else if #[cfg(feature = "network")] {
        type NetworkProver = NetworkProverV1;
    }
}

impl ProverClient {
    #[deprecated(since = "4.0.0", note = "use ProverClient::builder().from_env() instead")]
    pub fn new() -> Self {
        Self::builder().from_env()
    }

    pub fn builder() -> ProverClientBuilder {
        ProverClientBuilder::default()
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
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: SP1Stdin) -> SimpleExecute<'a> {
        SimpleExecute::new(self, elf, stdin)
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
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> SimpleProve<'a> {
        SimpleProve::new(self.prover.as_ref(), pk, stdin)
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
        Self::builder().from_env()
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct SimpleProve<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
}

impl<'a> SimpleProve<'a> {
    /// Prepare to prove the execution of the given program with the given input.
    ///
    /// Prefer using [ProverClient::prove](super::ProverClient::prove).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Self {
        Self { prover, kind: Default::default(), pk, stdin }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin } = self;

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        if std::env::var("SP1_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let program = pk.elf.clone();
            std::fs::write("program.bin", program).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write("stdin.bin", stdin.clone()).unwrap();
        }

        prover.prove(pk, stdin, kind)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SP1ProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::Plonk;
        self
    }

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = SP1ProofKind::Groth16;
        self
    }
}

/// Builder type for [`ProverClient`].
#[derive(Debug, Default)]
pub struct ProverClientBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
    skip_simulation: bool,
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

    /// Skips simulation. Only used for network prover.
    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    /// Builds a [ProverClient], filling in unset fields from environment variables.
    pub fn from_env(mut self) -> ProverClient {
        let mode = env::var("SP1_PROVER")
            .unwrap_or_else(|_| "local".to_string())
            .parse::<ProverMode>()
            .unwrap_or(ProverMode::Cpu);
        self.rpc_url = self.rpc_url.or_else(|| env::var("PROVER_NETWORK_RPC").ok());
        self.private_key = self.private_key.or_else(|| env::var("SP1_PRIVATE_KEY").ok());
        self.build(mode)
    }

    /// Builds a [ProverClient], using the provided mode.
    pub fn build(self, mode: ProverMode) -> ProverClient {
        let prover: Box<dyn Prover<DefaultProverComponents>> = match mode {
            ProverMode::Cpu => Box::new(CpuProver::new()),
            ProverMode::Cuda => {
                cfg_if! {
                    if #[cfg(feature = "cuda")] {
                        Box::new(CudaProver::new(SP1Prover::new()))
                    } else {
                        panic!("cuda feature is not enabled")
                    }
                }
            }
            ProverMode::Network => {
                let private_key = self.private_key.expect("The private key is required");

                cfg_if! {
                    if #[cfg(feature = "network-v2")] {
                        Box::new(NetworkProverV2::new(&private_key, self.rpc_url, self.skip_simulation))
                    } else if #[cfg(feature = "network")] {
                        Box::new(NetworkProverV1::new(&private_key, self.rpc_url, self.skip_simulation))
                    } else {
                        panic!("network feature is not enabled")
                    }
                }
            }
            ProverMode::Mock => Box::new(MockProver::new()),
        };
        ProverClient { prover }
    }

    /// Builds a [CpuProver] specifically for local CPU proving.
    pub fn cpu(self) -> CpuProver {
        CpuProver::new()
    }

    /// Builds a [CudaProver] specifically for local NVIDIA GPU proving.
    #[cfg(feature = "cuda")]
    pub fn cuda(self) -> CudaProver {
        CudaProver::new(SP1Prover::new())
    }

    /// Builds a [NetworkProver] specifically for network proving.
    #[cfg(any(feature = "network", feature = "network-v2"))]
    pub fn network(self) -> NetworkProver {
        NetworkProver::new(
            &self.private_key.expect("Private key must be set"),
            self.rpc_url,
            self.skip_simulation,
        )
    }

    /// Builds a [MockProver] specifically for mock proving.
    pub fn mock(self) -> MockProver {
        MockProver::new()
    }
}

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
pub struct SimpleExecute<'a> {
    prover: &'a ProverClient,
    elf: &'a [u8],
    stdin: SP1Stdin,
}

impl<'a> SimpleExecute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(prover: &'a ProverClient, elf: &'a [u8], stdin: SP1Stdin) -> Self {
        Self { prover, elf, stdin }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin } = self;
        Ok(prover.prover.sp1_prover().execute(elf, &stdin, Default::default())?)
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
