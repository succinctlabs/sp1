//! Prover components.

mod cpu;
mod memory_permit;
mod permits;
mod shard;
mod simple;
mod trace;
mod zerocheck;

pub use cpu::*;
pub use memory_permit::*;
pub use permits::*;
pub use shard::*;
pub use simple::*;
use slop_basefold_prover::BasefoldProver;
use slop_merkle_tree::BnProver;
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
pub use trace::*;
pub use zerocheck::*;

pub use slop_merkle_tree::Poseidon2KoalaBear16Prover as SP1MerkleTreeProver;

/// The CPU prover components for a jagged PCS prover in SP1. Jagged wraps this base (batch) PCS
/// prover in its own stacking layer internally.
pub type SP1InnerPcsProver = BasefoldProver<SP1GlobalContext, SP1MerkleTreeProver>;

/// The Jagged CPU prover components for the wrap step of recursion in SP1.
pub type SP1OuterPcsProver =
    BasefoldProver<SP1OuterGlobalContext, BnProver<SP1Field, SP1ExtensionField>>;
