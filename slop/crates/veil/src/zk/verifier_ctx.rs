use slop_algebra::TwoAdicField;
use slop_challenger::IopCtx;

/// Extension of [`IopCtx`] for IOP contexts that can be used with VEIL.
///
/// Currently, we simply limit this to hash based IOPs using Reed-Solomon encoding. Future
/// implementation can expend to other codes.
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {}

/// KoalaBear ZK context.
pub use slop_koala_bear::KoalaBearDegree4Duplex;

impl ZkIopCtx for KoalaBearDegree4Duplex {}

/// A zk verifier contex
pub struct ZkVerifierCtx {
    #[doc(hidden)]
    num: u32,
}
