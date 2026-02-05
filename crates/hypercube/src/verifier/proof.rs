use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use slop_challenger::{GrindingChallenger, IopCtx};
use slop_jagged::JaggedPcsProof;
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{MultilinearPcsVerifier, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_symmetric::PseudoCompressionFunction;
use sp1_primitives::{utils::reverse_bits_len, SP1GlobalContext};

use crate::{LogupGkrProof, MachineVerifyingKey, ShardContext};

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and
/// recursive proofs need to pad their public values vec to this length.  This is required since the
/// recursion verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 187;

/// Data required for testing.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>"
))]
// #[cfg(any(test, feature = "test-proof"))]
pub struct TestingData<GC: IopCtx> {
    /// The gkr points.
    pub gkr_points: Vec<Point<GC::EF>>,
    /// The challenger state just before the zerocheck.
    pub challenger_state: GC::Challenger,
}

/// A proof for a shard.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize, Proof: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>, Proof: Deserialize<'de>"
))]
pub struct ShardProof<GC: IopCtx, Proof> {
    /// The public values
    pub public_values: Vec<GC::F>,
    /// The commitments to main traces.
    pub main_commitment: GC::Digest,
    /// The Logup GKR IOP proof.
    pub logup_gkr_proof: LogupGkrProof<<GC::Challenger as GrindingChallenger>::Witness, GC::EF>,
    /// TH zerocheck IOP proof.
    pub zerocheck_proof: PartialSumcheckProof<GC::EF>,
    /// The values of the traces at the final random point.
    pub opened_values: ShardOpenedValues<GC::F, GC::EF>,
    /// The evaluation proof.
    pub evaluation_proof: JaggedPcsProof<GC, Proof>,
}

/// The `ShardProof` type generic in `GC` and `SC`.
pub type ShardContextProof<GC, SC> =
    ShardProof<GC, <<SC as ShardContext<GC>>::Config as MultilinearPcsVerifier<GC>>::Proof>;

/// The values of the chips in the shard at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<F, EF> {
    /// For each chip with respect to the canonical ordering, the values of the chip at the random
    /// point.
    pub chips: BTreeMap<String, ChipOpenedValues<F, EF>>,
}

/// The opening values for a given chip at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct ChipOpenedValues<F, EF> {
    /// The opening of the preprocessed trace.
    pub preprocessed: AirOpenedValues<EF>,
    /// The opening of the main trace.
    pub main: AirOpenedValues<EF>,
    /// The big-endian bit representation of the degree of the chip.
    pub degree: Point<F>,
}

/// The opening values for a given table section at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct AirOpenedValues<T> {
    /// The opening of the local trace
    pub local: Vec<T>,
}

impl<T> AirOpenedValues<T> {
    /// Organize the opening values into a vertical pair.
    #[must_use]
    pub fn view(&self) -> RowMajorMatrixView<'_, T>
    where
        T: Clone + Send + Sync,
    {
        RowMajorMatrixView::new_row(&self.local)
    }
}

/// A Merkle tree proof for proving membership in the recursion verifying key set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof<GC: IopCtx> {
    /// The index of the leaf being proven.
    pub index: usize,
    /// The Merkle path.
    pub path: Vec<GC::Digest>,
}

#[derive(Debug)]
/// The error type for Merkle proof verification.
pub struct VcsError;

/// Verify a Merkle proof.
pub fn verify_merkle_proof<GC: IopCtx>(
    proof: &MerkleProof<GC>,
    value: GC::Digest,
    commitment: GC::Digest,
) -> Result<(), VcsError> {
    let MerkleProof { index, path } = proof;

    let mut value = value;

    let mut index = reverse_bits_len(*index, path.len());

    for sibling in path {
        // If the index is odd, swap the order of [value, sibling].
        let new_pair = if index.is_multiple_of(2) { [value, *sibling] } else { [*sibling, value] };
        let (_, compressor) = GC::default_hasher_and_compressor();
        value = compressor.compress(new_pair);
        index >>= 1;
    }
    if value != commitment {
        Err(VcsError)
    } else {
        Ok(())
    }
}

/// An intermediate proof which proves the execution of a Hypercube verifier.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize, Proof: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>, Proof: Deserialize<'de>"
))]
pub struct SP1RecursionProof<GC: IopCtx, Proof> {
    /// The verifying key associated with the proof.
    pub vk: MachineVerifyingKey<GC>,
    /// The shard proof representing the shard proof.
    pub proof: ShardProof<GC, Proof>,
    /// The Merkle proof for the recursion verifying key.
    pub vk_merkle_proof: MerkleProof<SP1GlobalContext>,
}

impl<GC: IopCtx, Proof> std::fmt::Debug for SP1RecursionProof<GC, Proof> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SP1ReduceProof");
        // TODO: comment back after debug enabled.
        // debug_struct.field("vk", &self.vk);
        // debug_struct.field("proof", &self.proof);
        debug_struct.finish()
    }
}

/// An intermediate proof which proves the execution of a Hypercube verifier.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize, Proof: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>, Proof: Deserialize<'de>"
))]
pub struct SP1WrapProof<GC: IopCtx, Proof> {
    /// The verifying key associated with the proof.
    pub vk: MachineVerifyingKey<GC>,
    /// The shard proof within the wrap proof.
    pub proof: ShardProof<GC, Proof>,
}
