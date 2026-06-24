use anyhow::Result;
use clap::ValueEnum;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{air::ShardRange, SP1PcsProofInner, ShardProof};
use sp1_primitives::{io::SP1PublicValues, SP1GlobalContext};
use sp1_recursion_circuit::machine::{
    SP1CompressWithVKeyWitnessValues, SP1DeferredWitnessValues, SP1NormalizeWitnessValues,
};
pub use sp1_recursion_gnark_ffi::proof::{Groth16Bn254Proof, PlonkBn254Proof};
use std::{fs::File, path::Path};
use thiserror::Error;

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P: Clone> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub cycles: u64,
}

impl<P: Serialize + DeserializeOwned + Clone> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug + Clone> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata").field("proof", &self.proof).finish()
    }
}

/// A proof of an SP1 program without any wrapping.
pub type SP1CoreProof = SP1ProofWithMetadata<SP1CoreProofData>;

/// An SP1 proof that has been recursively reduced into a single proof. This proof can be
/// verified within SP1 programs.
pub type SP1ReducedProof = SP1ProofWithMetadata<SP1ReducedProofData>;

/// An SP1 proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type SP1PlonkBn254Proof = SP1ProofWithMetadata<SP1PlonkBn254ProofData>;

/// An SP1 proof that has been wrapped into a single Groth16 proof and can be verified onchain.
pub type SP1Groth16Bn254Proof = SP1ProofWithMetadata<SP1Groth16Bn254ProofData>;

/// An SP1 proof that has been wrapped into a single proof and can be verified onchain.
pub type SP1Proof = SP1ProofWithMetadata<SP1Bn254ProofData>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1CoreProofData(pub Vec<ShardProof<SP1GlobalContext, SP1PcsProofInner>>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1ReducedProofData(pub ShardProof<SP1GlobalContext, SP1PcsProofInner>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1PlonkBn254ProofData(pub PlonkBn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1Groth16Bn254ProofData(pub Groth16Bn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub enum SP1Bn254ProofData {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

impl SP1Bn254ProofData {
    pub fn get_proof_system(&self) -> ProofSystem {
        match self {
            SP1Bn254ProofData::Plonk(_) => ProofSystem::Plonk,
            SP1Bn254ProofData::Groth16(_) => ProofSystem::Groth16,
        }
    }

    pub fn get_raw_proof(&self) -> &str {
        match self {
            SP1Bn254ProofData::Plonk(proof) => &proof.raw_proof,
            SP1Bn254ProofData::Groth16(proof) => &proof.raw_proof,
        }
    }
}

/// The mode of the prover.
#[derive(Debug, Default, Clone, ValueEnum, PartialEq, Eq)]
pub enum ProverMode {
    #[default]
    Cpu,
    Cuda,
    Network,
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Plonk,
    Groth16,
}

impl ProofSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::Plonk => "Plonk",
            ProofSystem::Groth16 => "Groth16",
        }
    }
}

#[derive(Error, Debug)]
pub enum SP1RecursionProverError {
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

pub type SP1CompressWitness = SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>;

/// Which compose-program family a `Compress` witness targets. The two stages chain public values
/// differently (within-chunk binds the shared transcript and closes `Σ gcs = 0`; across-chunk
/// chains boundary state with timestamp resets), so the executor selects the program by scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeScope {
    /// Reduce same-chunk proofs.
    WithinChunk,
    /// Reduce per-chunk proofs.
    AcrossChunk,
}

#[allow(clippy::large_enum_variant)]
pub enum SP1CircuitWitness {
    Core(SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner>),
    Deferred(SP1DeferredWitnessValues<SP1GlobalContext, SP1PcsProofInner>),
    Compress { witness: SP1CompressWitness, scope: ComposeScope },
    Shrink(SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>),
    Wrap(SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>),
}

impl SP1CircuitWitness {
    pub fn range(&self) -> ShardRange {
        match self {
            SP1CircuitWitness::Core(input) => input.range(),
            SP1CircuitWitness::Deferred(input) => input.range(),
            SP1CircuitWitness::Compress { witness, .. } => witness.compress_val.range(),
            SP1CircuitWitness::Shrink(_) => {
                unimplemented!("Shrink witness does not need to have a range")
            }
            SP1CircuitWitness::Wrap(_) => {
                unimplemented!("Wrap witness does not need to have a range")
            }
        }
    }
}
