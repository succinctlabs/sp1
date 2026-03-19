use serde::de::DeserializeOwned;
use serde::Serialize;
use slop_algebra::TwoAdicField;
use slop_challenger::IopCtx;

/// Extension of [`IopCtx`] for IOP contexts that can be used with VEIL.
///
/// Currently, we simply limit this to hash based IOPs using Reed-Solomon encoding. Future
/// implementation can expend to other codes.
///
/// The `PcsProof` associated type identifies the proof type produced by the PCS scheme
/// used with this context. Verifier and proof types are parameterized by this context
/// alone (no separate `PcsProof` generic).
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {
    /// The PCS proof type for this context.
    type PcsProof: Clone + Serialize + DeserializeOwned;
}
