//! # SP1 Environment Prover
//!
//! A prover that can execute programs and generate proofs with a different implementation based on
//! the value of certain environment variables.

mod prove;

use std::env;

use anyhow::Result;
use prove::EnvProveBuilder;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::CpuProverComponents, SP1Prover, SP1ProvingKey, SP1VerifyingKey};

use super::{Prover, SP1VerificationError};
#[cfg(feature = "network")]
use crate::network::builder::NetworkProverBuilder;
use crate::{
    cpu::{execute::CpuExecuteBuilder, CpuProver},
    cuda::CudaProver,
    SP1ProofMode, SP1ProofWithPublicValues,
};

/// A prover that can execute programs and generate proofs with a different implementation based on
/// the value of certain environment variables.
///
/// The environment variables are described in [`EnvProver::new`].
pub struct EnvProver {
    pub(crate) prover: Box<dyn Prover<CpuProverComponents>>,
}

impl EnvProver {
    /// Creates a new [`EnvProver`] with the given configuration.
    ///
    /// The following environment variables are used to configure the prover:
    /// - `SP1_PROVER`: The type of prover to use. Must be one of `mock`, `local`, `cuda`, or
    ///   `network`.
    /// - `NETWORK_PRIVATE_KEY`: The private key to use for the network prover.
    /// - `NETWORK_RPC_URL`: The RPC URL to use for the network prover.
    #[must_use]
    pub fn new() -> Self {
        let mode = if let Ok(mode) = env::var("SP1_PROVER") {
            mode
        } else {
            tracing::warn!("SP1_PROVER environment variable not set, defaulting to 'cpu'");
            "cpu".to_string()
        };

        let prover: Box<dyn Prover<CpuProverComponents>> = match mode.as_str() {
            "mock" => Box::new(CpuProver::mock()),
            "cpu" => Box::new(CpuProver::new()),
            "cuda" => {
                Box::new(CudaProver::new(SP1Prover::new(), None))
            }
            "network" => {
                #[cfg(not(feature = "network"))]
                panic!(
                    r#"The network prover requires the 'network' feature to be enabled.
                    Please enable it in your Cargo.toml with:
                    sp1-sdk = {{ version = "...", features = ["network"] }}"#
                );

                #[cfg(feature = "network")]
                {
                    Box::new(NetworkProverBuilder::default().build())
                }
            }
            _ => panic!(
                "Invalid SP1_PROVER value. Expected one of: mock, cpu, cuda, or network. Got: '{mode}'.\n\
                Please set the SP1_PROVER environment variable to one of the supported values."
            ),
        };
        EnvProver { prover }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// The builder is used for both the [`crate::cpu::CpuProver`] and [`crate::CudaProver`] client
    /// types.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    #[must_use]
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: self.prover.inner(),
            elf,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
        }
    }

    /// Creates a new [`EnvProve`] for proving a program on the CPU.
    ///
    /// # Details
    /// The builder is used for only the [`crate::cpu::CpuProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).core().run();
    /// ```
    #[must_use]
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: &'a SP1Stdin) -> EnvProveBuilder<'a> {
        EnvProveBuilder {
            prover: self.prover.as_ref(),
            mode: SP1ProofMode::Core,
            pk,
            stdin: stdin.clone(),
        }
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [`Self::setup`].
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    #[must_use]
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Default for EnvProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover<CpuProverComponents> for EnvProver {
    fn inner(&self) -> &SP1Prover<CpuProverComponents> {
        self.prover.inner()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove(pk, stdin, mode)
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.prover.verify(bundle, vkey)
    }
}
