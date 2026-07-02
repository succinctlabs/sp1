pub mod basefold_zk_wrapper;
pub mod padding;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use basefold_zk_wrapper::*;
pub use padding::*;
pub use prover::*;
pub use verifier::*;

/// Param-less marker that gates the blanket [`crate::zk::inner::ZkPcsProver`] impl. A stacked
/// prover implements [`sealed::Sealed`] to opt into that blanket impl; the `NoPcsProver` null
/// object deliberately does **not**, which is what lets the blanket impl coexist with
/// `NoPcsProver`'s direct impl without a coherence conflict (a param-less bound lets the compiler
/// prove `NoPcsProver: !Sealed`). The verifier side needs no marker: [`ZkStackedVerifier`] is a
/// concrete wrapper type, so its [`crate::zk::inner::ZkPcsVerifier`] impl is not a blanket impl.
pub(in crate::zk::stacked_pcs) mod sealed {
    /// See the [module docs](self).
    pub trait Sealed {}
}

use crate::zk::inner::{ZkIopCtx, ZkMerkleizer};
use slop_algebra::TwoAdicField;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_basefold_prover::BasefoldProver;

// The stacked-default MLE-decomposition helpers live in the `slop-stacked` crate (they are
// PCS-agnostic eq-stacking math). Re-export the block-convention helpers here for the stacked-PCS
// call sites.
pub use slop_stacked::{stacked_oracle_eval, stacked_reduced_point};

/// Creates both a Basefold-backed stacked PCS prover and verifier with default FRI configuration.
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
) -> (BasefoldProver<GC, MK>, ZkBasefoldVerifier<GC>)
where
    GC::F: TwoAdicField,
{
    let fri_config = FriConfig::default_fri_config();
    // The Basefold verifier pins the encoding width (= stacking height); the prover inherits it.
    let basefold_verifier =
        BasefoldVerifier::<GC>::new(fri_config, num_expected_commitments, num_encoding_variables);
    let basefold_prover = BasefoldProver::new(&basefold_verifier);
    // The ZK layer drives the base PCS purely through `BatchPcsProver`, so the Basefold prover and
    // verifier are used directly — no `slop-stacked` interleaving wrapper is involved.
    let zk_verifier = ZkStackedVerifier::new(basefold_verifier);
    (basefold_prover, zk_verifier)
}
