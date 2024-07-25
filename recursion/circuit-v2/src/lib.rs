//! Copied from [`sp1_recursion_program`].

use sp1_recursion_compiler::ir::{Config, Ext, Felt};
use sp1_recursion_core_v2::DIGEST_SIZE;

pub mod build_wrap_v2;
pub mod challenger;
pub mod fri;

pub type DigestVariable<C> = [Felt<<C as Config>::F>; DIGEST_SIZE];
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<DigestVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C>>,
}
