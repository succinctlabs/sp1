use std::env;

use crate::util::dump_proof_input;
use crate::{SP1ProofKind, SP1ProofWithPublicValues};
use anyhow::Result;
use cfg_if::cfg_if;
use sp1_core_executor::ExecutionReport;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1ProvingKey, SP1VerifyingKey};

#[cfg(feature = "cuda")]
use super::CudaProver;
use super::{CpuProver, Prover, ProverType, SP1VerificationError};

/// A prover that allows executing programs and generating proofs. The actual implementation depends
/// on the value of the `SP1_PROVER` environment variable, and other settings may be loaded from env.
pub struct EnvProver {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

impl EnvProver {
    pub fn new() -> Self {
        let mode = env::var("SP1_PROVER").unwrap_or_else(|_| "local".to_string());

        let prover: Box<dyn Prover<DefaultProverComponents>> = match mode.as_str() {
            "local" => Box::new(CpuProver::new(false)),
            "cuda" => {
                cfg_if! {
                    if #[cfg(feature = "cuda")] {
                        Box::new(CudaProver::new(SP1Prover::new()))
                    } else {
                        panic!("cuda sp1-sdk feature is not enabled")
                    }
                }
            }
            "network" => {
                let rpc_url = env::var("PROVER_NETWORK_RPC").ok();
                let private_key = env::var("SP1_PRIVATE_KEY").expect("SP1_PRIVATE_KEY must be set");

                cfg_if! {
                    if #[cfg(feature = "network-v2")] {
                        Box::new(crate::NetworkProverV2::new(&private_key, rpc_url))
                    } else if #[cfg(feature = "network")] {
                        Box::new(crate::NetworkProverV1::new(&private_key, rpc_url))
                    } else {
                        panic!("network sp1-sdk feature is not enabled")
                    }
                }
            }
            "mock" => Box::new(CpuProver::new(true)),
            _ => panic!("invalid SP1_PROVER value"),
        };
        EnvProver { prover }
    }

    /// Execute the given program on the given input (without generating a proof). Returns the
    /// public values and execution report of the program after it has been executed.
    pub fn execute<'a>(
        &'a self,
        elf: &'a [u8],
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport)> {
        Ok(self.prover.sp1_prover().execute(elf, &stdin, Default::default())?)
    }

    /// Prepare to prove the execution of the given program with the given input in the default
    /// mode. The returned [EnvProve] may be configured via its methods before running.
    /// For example, calling [EnvProve::compressed] sets the mode to compressed mode.
    ///
    /// To prove, call [EnvProve::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [EnvProve::compressed],
    /// [EnvProve::plonk], or [EnvProve::groth16] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Context, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::env();
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
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> EnvProve<'a> {
        EnvProve::new(self.prover.as_ref(), pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::env();
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

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Default for EnvProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover<DefaultProverComponents> for EnvProver {
    fn id(&self) -> ProverType {
        self.prover.id()
    }

    fn sp1_prover(&self) -> &SP1Prover<DefaultProverComponents> {
        self.prover.sp1_prover()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove(pk, stdin, kind)
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct EnvProve<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
}

impl<'a> EnvProve<'a> {
    fn new(
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
        dump_proof_input(&pk.elf, &stdin);

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

    /// Set the proof mode to the given mode.
    pub fn mode(mut self, mode: SP1ProofKind) -> Self {
        self.kind = mode;
        self
    }
}
