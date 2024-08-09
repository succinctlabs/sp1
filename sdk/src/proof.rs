use std::{fmt::Debug, fs::File, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumDiscriminants, EnumTryAs};

use sp1_core::stark::{MachineVerificationError, ShardProof};
use sp1_prover::{CoreSC, InnerSC, PlonkBn254Proof, SP1PublicValues, SP1Stdin};

/// A proof generated with SP1 of a particular proof mode.
#[derive(Debug, Clone, Serialize, Deserialize, EnumDiscriminants, EnumTryAs)]
#[strum_discriminants(derive(Default, Hash, PartialOrd, Ord))]
#[strum_discriminants(name(SP1ProofKind))]
pub enum SP1Proof {
    #[strum_discriminants(default)]
    Core(Vec<ShardProof<CoreSC>>),
    Compressed(ShardProof<InnerSC>),
    Plonk(PlonkBn254Proof),
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
            SP1Proof::Plonk(plonk) => plonk.raw_proof().clone(),
            _ => unimplemented!(),
        }
    }

    /// For Plonk proofs, returns the proof in a byte encoding the onchain verifier accepts.
    /// The bytes consist of the first four bytes of Plonk vkey hash followed by the encoded proof.
    pub fn bytes(&self) -> Vec<u8> {
        match &self.proof {
            SP1Proof::Plonk(plonk_proof) => {
                let encoded_proof = plonk_proof.encoded_proof();
                let vkey_hash = plonk_proof.plonk_vkey_hash();
                let mut bytes = Vec::with_capacity(4 + encoded_proof.len());
                bytes.extend_from_slice(&vkey_hash[..4]);
                bytes.extend_from_slice(encoded_proof.as_bytes());
                bytes
            }
            _ => unimplemented!("only Plonk proofs are verifiable onchain"),
        }
    }
}

pub type SP1CoreProofVerificationError = MachineVerificationError<CoreSC>;

pub type SP1CompressedProofVerificationError = MachineVerificationError<InnerSC>;
