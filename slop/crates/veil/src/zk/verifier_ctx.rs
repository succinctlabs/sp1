use slop_algebra::TwoAdicField;
use slop_challenger::IopCtx;

/// Extension of [`IopCtx`] for ZK proofs (field constraints only).
///
/// Verifiers only need this trait. Prover code that requires merkle commitments
/// should additionally constrain a separate `MK: ZkMerkleizer<GC>` parameter.
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {}

/// KoalaBear ZK context.
pub use slop_koala_bear::KoalaBearDegree4Duplex;

impl ZkIopCtx for KoalaBearDegree4Duplex {}

/// A zk verifier contex
pub struct ZkVerifierCtx {
    #[doc(hidden)]
    num: u32,
}
