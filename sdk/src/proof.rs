use std::{fmt::Debug, fs::File, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumDiscriminants, EnumTryAs};

use sp1_core::stark::{MachineVerificationError, ShardProof};
use sp1_prover::{CoreSC, InnerSC, PlonkBn254Proof, SP1PublicValues, SP1Stdin};

/// A proof generated with SP1 of a particular proof mode.
#[derive(Debug, Clone, Serialize, Deserialize, EnumDiscriminants, EnumTryAs)]
#[strum_discriminants(derive(Default, Hash, PartialOrd, Ord))]
#[strum_discriminants(name(SP1ProofKind), vis(pub(crate)))]
pub enum SP1Proof {
    #[strum_discriminants(default)]
    Core(Vec<ShardProof<CoreSC>>),
    Compress(ShardProof<InnerSC>),
    PlonkBn254(PlonkBn254Proof),
}

/// A proof generated with SP1, bundled together with stdin, public values, and the SP1 version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1ProofBundle {
    pub proof: SP1Proof,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub sp1_version: String,
}

impl SP1ProofBundle {
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
}

pub type SP1CoreProofVerificationError = MachineVerificationError<CoreSC>;

pub type SP1CompressedProofVerificationError = MachineVerificationError<InnerSC>;
