pub mod basefold_prover_wrapper;
pub mod basefold_verifier_wrapper;
pub mod prover;
pub mod utils;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use basefold_verifier_wrapper::*;
pub use prover::*;
pub use verifier::*;

use crate::zk::verifier_ctx::ZkIopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;

impl ZkIopCtx for KoalaBearDegree4Duplex {
    type PcsProof = ZkStackedPcsProof<KoalaBearDegree4Duplex>;

    type PcsVerifier = ZkStackedPcsVerifier<Self>;
}
