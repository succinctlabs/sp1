use std::{fmt::Debug, fs::File, path::Path};

use anyhow::Result;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use strum_macros::{EnumDiscriminants, EnumTryAs};

use sp1_core::stark::{MachineVerificationError, ShardProof};
use sp1_prover::{CoreSC, InnerSC, PlonkBn254Proof, SP1PublicValues, SP1Stdin};

/// A proof generated with SP1, tagged with the kind.
#[derive(EnumDiscriminants, EnumTryAs, Debug, Clone, Serialize, Deserialize)]
#[strum_discriminants(derive(Default, Hash, PartialOrd, Ord))]
#[strum_discriminants(name(SP1ProofKind), vis(pub(crate)))]
pub enum SP1Proof {
    #[strum_discriminants(default)]
    Core(SP1CoreProof),
    Compress(SP1CompressedProof),
    // Shrink,
    // Wrap,
    PlonkBn254(SP1PlonkBn254Proof),
}

impl SP1Proof {
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

/// A proof generated with SP1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize + Debug + Clone"))]
#[serde(bound(deserialize = "P: DeserializeOwned + Debug + Clone"))]
pub struct SP1ProofWithPublicValues<P> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub sp1_version: String,
}

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove].
pub type SP1CoreProof = SP1ProofWithPublicValues<Vec<ShardProof<CoreSC>>>;
pub type SP1CoreProofVerificationError = MachineVerificationError<CoreSC>;

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove_compressed].
pub type SP1CompressedProof = SP1ProofWithPublicValues<ShardProof<InnerSC>>;
pub type SP1CompressedProofVerificationError = MachineVerificationError<InnerSC>;

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove_plonk].
pub type SP1PlonkBn254Proof = SP1ProofWithPublicValues<PlonkBn254Proof>;
