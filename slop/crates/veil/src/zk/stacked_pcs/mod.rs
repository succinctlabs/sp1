pub mod basefold_prover_wrapper;
pub mod prover;
pub mod utils;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use prover::*;
pub use verifier::*;

use crate::zk::inner::{ZkIopCtx, ZkMerkleizer};
use basefold_prover_wrapper::ZkBasefoldProver;
use slop_algebra::TwoAdicField;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_basefold_prover::BasefoldProver;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_stacked::StackedPcsVerifier;

impl ZkIopCtx for KoalaBearDegree4Duplex {
    type PcsProof = ZkStackedPcsProof<KoalaBearDegree4Duplex>;

    type PcsVerifier = StackedPcsVerifier<Self>;
}

/// Creates both a `ZkBasefoldProver` and a `StackedPcsVerifier` with default FRI configuration.
///
/// This is a convenience function that simplifies the typical setup where you need both
/// a prover and verifier. The underlying `BasefoldVerifier` is shared (prover borrows it
/// before verifier takes ownership).
///
/// The `num_encoding_variables` value is fixed here and all subsequent
/// [`commit_mle`](crate::zk::ZkProverCtx::commit_mle) and
/// [`read_oracle`](crate::compiler::ReadingCtx::read_oracle) calls must use a matching
/// `num_encoding_variables` (inferred from the MLE size for `commit_mle`, or passed
/// directly for `read_oracle`).
///
/// # Arguments
/// * `num_expected_commitments` — upper bound on the number of MLE commitments that
///   will be made during the protocol.
/// * `num_encoding_variables` — number of variables per stacked polynomial (encoding
///   width). Each committed MLE will be stacked into a tensor whose rows have
///   `2^num_encoding_variables` entries.
pub fn initialize_zk_prover_and_verifier<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>(
    num_expected_commitments: usize,
    num_encoding_variables: u32,
) -> (ZkBasefoldProver<GC, MK>, StackedPcsVerifier<GC>)
where
    GC::F: TwoAdicField,
{
    let fri_config = FriConfig::default_fri_config();
    let basefold_verifier = BasefoldVerifier::<GC>::new(fri_config, num_expected_commitments);
    let basefold_prover = BasefoldProver::new(&basefold_verifier);
    let zk_basefold_prover = ZkBasefoldProver::new(basefold_prover);
    let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_encoding_variables);
    (zk_basefold_prover, stacked_verifier)
}
