use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_merkle_tree::{ComputeTcsOpenings, TensorCsProver};

pub mod constraints;
#[cfg(sp1_debug_constraints)]
pub mod debug;
pub mod mask_counter;
pub mod pcs_traits;
pub mod prover;
pub mod prover_transcript;
pub mod transcript;
pub mod verifier;
pub mod verifier_transcript;

#[cfg(test)]
mod tests;

pub use constraints::*;
pub use mask_counter::*;
pub use pcs_traits::*;
pub use prover::*;
pub use prover_transcript::*;
pub use transcript::*;
pub use verifier::*;
pub use verifier_transcript::*;

/// Extension of [`IopCtx`] for ZK proofs (field constraints only).
///
/// Verifiers only need this trait. Prover code that requires merkle commitments
/// should additionally constrain a separate `MK: ZkMerkleizer<GC>` parameter.
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {}

/// Auto-implemented trait that bundles the merkle commitment bounds needed by prover code.
///
/// Any type implementing `TensorCsProver + ComputeTcsOpenings + Default` automatically
/// satisfies this trait. Pass it as a separate generic `MK: ZkMerkleizer<GC>` on
/// prover-side structs and functions instead of baking it into `ZkIopCtx`.
pub trait ZkMerkleizer<GC: IopCtx>:
    TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend> + Default
{
}

impl<MK, GC: IopCtx> ZkMerkleizer<GC> for MK where
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend> + Default
{
}

/// Type alias for the prover data produced by a `ZkMerkleizer`.
pub type MerkleProverData<GC, MK> = <MK as TensorCsProver<GC, CpuBackend>>::ProverData;

/// KoalaBear ZK context.
pub use slop_koala_bear::KoalaBearDegree4Duplex;

impl ZkIopCtx for KoalaBearDegree4Duplex {}

/// Names the most recently added linear constraint for debugging purposes.
///
/// When compiled with `RUSTFLAGS="--cfg sp1_debug_constraints"`, this macro
/// calls `name_last_lin_constraint` on the provided context to associate
/// a human-readable name with the last added constraint. If the constraint
/// fails during proof generation, the name will be displayed instead of just the index.
///
/// When compiled without the flag, this macro expands to nothing.
///
/// # Example
///
/// ```ignore
/// builder.add_lin_constraint(constraint);
/// name_constraint!(builder, "sumcheck round 3 equality");
///
/// // Or with a formatted string:
/// name_constraint!(builder, "round {} check", round_num);
/// ```
#[macro_export]
macro_rules! name_constraint {
    ($ctx:expr, $name:expr) => {{
        #[cfg(sp1_debug_constraints)]
        $crate::zk::inner::ConstraintContextInnerExt::name_last_lin_constraint(&$ctx, $name);
    }};
    ($ctx:expr, $fmt:expr, $($arg:tt)*) => {{
        #[cfg(sp1_debug_constraints)]
        $crate::zk::inner::ConstraintContext::name_last_lin_constraint(&$ctx, format!($fmt, $($arg)*));
     }};
}
