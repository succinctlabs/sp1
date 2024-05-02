//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod proto {
    #[rustfmt::skip]
    pub mod network;
}
pub mod artifacts;
pub mod auth;
pub mod client;
pub mod provers;
pub mod utils;

use std::{env, fs::File, path::Path};

use anyhow::{Ok, Result};
use provers::{LocalProver, MockProver, NetworkProver, Prover};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core::stark::ShardProof;
pub use sp1_prover::{
    CoreSC, Groth16Proof, InnerSC, PlonkBn254Proof, SP1CoreProof, SP1Prover, SP1ProvingKey,
    SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};

/// A client for interacting with SP1.
pub struct ProverClient {
    pub prover: Box<dyn Prover>,
}

impl ProverClient {
    /// Creates a new [ProverClient].
    ///
    /// Setting the `SP1_PROVER` enviroment variable can change the prover used under the hood.
    /// - `local` (default): Uses [LocalProver]. Recommended for proving end-to-end locally.
    /// - `mock`: Uses [MockProver]. Recommended for testing and development.
    /// - `remote`: Uses [NetworkProver]. Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::new();
    /// ```
    pub fn new() -> Self {
        match env::var("SP1_PROVER")
            .unwrap_or("local".to_string())
            .to_lowercase()
            .as_str()
        {
            "mock" => Self {
                prover: Box::new(MockProver::new()),
            },
            "local" => Self {
                prover: Box::new(LocalProver::new()),
            },
            "remote" => Self {
                prover: Box::new(NetworkProver::new()),
            },
            _ => panic!(
                "invalid value for SP1_PROVER enviroment variable: expected 'local', 'mock', or 'remote'"
            ),
        }
    }

    /// Executes the given program on the given input (without generating a proof).
    ///
    /// Returns the public values of the program after it has been executed.
    ///
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let public_values = client.execute(elf, stdin).unwrap();
    /// ```
    pub fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<SP1PublicValues> {
        Ok(SP1Prover::execute(elf, &stdin))
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new();
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf).unwrap();
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    /// Proves the execution of the given program with the given input in the default mode.
    ///
    /// Returns a proof of the program's execution. By default the proof generated will not be
    /// compressed to constant size. To create a more succinct proof, use the [Self::prove_compressed],
    /// [Self::prove_groth16], or [Self::prove_plonk] methods.
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).unwrap();
    /// ```
    pub fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        self.prover.prove(pk, stdin)
    }

    /// Proves the execution of the given program with the given input in the compressed mode.
    ///
    /// Returns a compressed proof of the program's execution. The compressed proof is a succinct
    /// proof that is of constant size and friendly for recursion and off-chain verification.
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_compressed(&pk, stdin).unwrap();
    /// ```
    pub fn prove_compressed(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Result<SP1CompressedProof> {
        self.prover.prove_compressed(pk, stdin)
    }

    /// Proves the execution of the given program with the given input in the groth16 mode.
    ///
    /// Returns a proof of the program's execution in the groth16 format. The proof is a succinct
    /// proof that is of constant size and friendly for on-chain verification.
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_groth16(&pk, stdin).unwrap();
    /// ```
    /// Generates a groth16 proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        self.prover.prove_groth16(pk, stdin)
    }

    /// Proves the execution of the given program with the given input in the plonk mode.
    ///
    /// Returns a proof of the program's execution in the plonk format. The proof is a succinct
    /// proof that is of constant size and friendly for on-chain verification.
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_plonk(&pk, stdin).unwrap();
    /// ```
    pub fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        self.prover.prove_plonk(pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(elf).unwrap();
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(&self, proof: &SP1Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify(proof, vkey)
    }

    /// Verifies that the given compressed proof is valid and matches the given verification key
    /// produced by [Self::setup].
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_compressed(&pk, stdin).unwrap();
    /// client.verify_compressed(&proof, &vk).unwrap();
    /// ```
    pub fn verify_compressed(
        &self,
        proof: &SP1CompressedProof,
        vkey: &SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_compressed(proof, vkey)
    }

    /// Verifies that the given groth16 proof is valid and matches the given verification key
    /// produced by [Self::setup].
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_groth16(&pk, stdin).unwrap();
    ///
    /// // Verify the proof.
    /// client.verify_groth16(&proof, &vk).unwrap();
    /// ```
    pub fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_groth16(proof, vkey)
    }

    /// Verifies that the given plonk proof is valid and matches the given verification key
    /// produced by [Self::setup].
    ///
    /// ### Examples
    /// ```
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../program/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf).unwrap();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_plonk(&pk, stdin).unwrap();
    ///
    /// // Verify the proof.
    /// client.verify_plonk(&proof, &vk).unwrap();
    /// ```
    pub fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_plonk(proof, vkey)
    }
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

impl<P: Serialize + DeserializeOwned> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata")
            .field("proof", &self.proof)
            .finish()
    }
}

pub type SP1Proof = SP1ProofWithMetadata<Vec<ShardProof<CoreSC>>>;

pub type SP1CompressedProof = SP1ProofWithMetadata<ShardProof<InnerSC>>;

pub type SP1Groth16Proof = SP1ProofWithMetadata<Groth16Proof>;

pub type SP1PlonkProof = SP1ProofWithMetadata<PlonkBn254Proof>;
