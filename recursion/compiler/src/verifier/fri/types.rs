use sp1_recursion_derive::DslVariable;

use crate::prelude::{Array, Builder, Config, Felt, MemVariable, Ptr, Usize, Var, Variable};

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L54
#[allow(type_alias_bounds)]
pub type Commitment<C: Config> = Array<C, Felt<C::F>>;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/config.rs#L1
#[derive(DslVariable, Clone)]
pub struct FriConfig<C: Config> {
    pub log_blowup: Var<C::N>,
    pub num_queries: Var<C::N>,
    pub proof_of_work_bits: Var<C::N>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(DslVariable, Clone)]
pub struct FriProof<C: Config> {
    pub commit_phase_commits: Array<C, Commitment<C>>,
    pub query_proofs: Array<C, FriQueryProof<C>>,
    pub final_poly: Felt<C::F>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(DslVariable, Clone)]
pub struct FriQueryProof<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStep<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Array<C, Commitment<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(DslVariable, Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Array<C, Var<C::N>>,
    pub betas: Array<C, Felt<C::F>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/matrix/src/lib.rs#L38
#[derive(DslVariable, Clone)]
pub struct Dimensions<C: Config> {
    pub height: Var<C::N>,
}
