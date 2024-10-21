use std::{fmt::Debug, fs::File, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sp1_core_executor::SP1ReduceProof;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use strum_macros::{EnumDiscriminants, EnumTryAs};

use sp1_prover::{CoreSC, Groth16Bn254Proof, InnerSC, PlonkBn254Proof};
use sp1_stark::{MachineVerificationError, ShardProof};

/// A proof generated with SP1 of a particular proof mode.
#[derive(Debug, Clone, Serialize, Deserialize, EnumDiscriminants, EnumTryAs)]
#[strum_discriminants(derive(Default, Hash, PartialOrd, Ord))]
#[strum_discriminants(name(SP1ProofKind))]
pub enum SP1Proof {
    #[strum_discriminants(default)]
    Core(Vec<ShardProof<CoreSC>>),
    Compressed(Box<SP1ReduceProof<InnerSC>>),
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

/// A proof generated with SP1, bundled together with stdin, public values, and the SP1 version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1ProofWithPublicValues {
    pub proof: SP1Proof,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub sp1_version: String,
}

impl SP1ProofWithPublicValues {
    /// Saves the proof to a path.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    /// Loads a proof from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }

    /// Returns the raw proof as a string.
    pub fn raw(&self) -> String {
        match &self.proof {
            SP1Proof::Plonk(plonk) => plonk.raw_proof.clone(),
            SP1Proof::Groth16(groth16) => groth16.raw_proof.clone(),
            _ => unimplemented!(),
        }
    }

    /// For Plonk or Groth16 proofs, returns the proof in a byte encoding the onchain verifier
    /// accepts. The bytes consist of the first four bytes of Plonk vkey hash followed by the
    /// encoded proof.
    pub fn bytes(&self) -> Vec<u8> {
        match &self.proof {
            SP1Proof::Plonk(plonk_proof) => {
                if plonk_proof.encoded_proof.is_empty() {
                    // If the proof is empty, then this is a mock proof. The mock SP1 verifier
                    // expects an empty byte array for verification, so return an empty byte array.
                    return Vec::new();
                }

                let mut bytes = Vec::with_capacity(4 + plonk_proof.encoded_proof.len());
                bytes.extend_from_slice(&plonk_proof.plonk_vkey_hash[..4]);
                bytes.extend_from_slice(
                    &hex::decode(&plonk_proof.encoded_proof).expect("Invalid Plonk proof"),
                );
                bytes
            }
            SP1Proof::Groth16(groth16_proof) => {
                if groth16_proof.encoded_proof.is_empty() {
                    // If the proof is empty, then this is a mock proof. The mock SP1 verifier
                    // expects an empty byte array for verification, so return an empty byte array.
                    return Vec::new();
                }

                let mut bytes = Vec::with_capacity(4 + groth16_proof.encoded_proof.len());
                bytes.extend_from_slice(&groth16_proof.groth16_vkey_hash[..4]);
                bytes.extend_from_slice(
                    &hex::decode(&groth16_proof.encoded_proof).expect("Invalid Groth16 proof"),
                );
                bytes
            }
            _ => unimplemented!("only Plonk and Groth16 proofs are verifiable onchain"),
        }
    }
}

pub type SP1CoreProofVerificationError = MachineVerificationError<CoreSC>;

pub type SP1CompressedProofVerificationError = MachineVerificationError<InnerSC>;
