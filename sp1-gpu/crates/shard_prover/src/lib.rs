//! The integration of all the prover components.
mod prover;
mod setup;
mod types;

pub use prover::*;
pub use sp1_gpu_jagged_tracegen::CORE_MAX_TRACE_SIZE;
pub use sp1_gpu_utils::{Ext, Felt};
pub use types::*;
