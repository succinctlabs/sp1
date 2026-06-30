mod dot_product;
mod error_correcting_code;
mod hadamard_product;
mod inner;
mod mask_counter;
mod no_pcs;
mod prover_ctx;
mod verifier_ctx;

use slop_algebra::TwoAdicField;
use slop_challenger::IopCtx;

/// Extension of [`IopCtx`] for IOP contexts that can be used with VEIL.
///
/// Currently, we simply limit this to hash based IOPs using Reed-Solomon encoding (i.e. an
/// [`IopCtx`] whose field and extension field are two-adic). Future implementations can expand to
/// other codes.
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>> ZkIopCtx for GC {}

pub use inner::{ZkPcsProver, ZkPcsVerifier, ZkProof, ZkProveError};
pub use prover_ctx::ZkProverCtxInitError;
pub mod stacked_pcs;

pub use mask_counter::*;
pub use no_pcs::*;
pub use prover_ctx::*;
pub use verifier_ctx::*;
