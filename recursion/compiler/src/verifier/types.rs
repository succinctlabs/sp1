use crate::prelude::{Config, Felt};
use std::marker::PhantomData;

pub const DIGEST_SIZE: usize = 8;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L54
#[allow(type_alias_bounds)]
pub type Hash<C: Config> = [Felt<C::F>; DIGEST_SIZE];

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/config.rs#L1
pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
pub struct FmtQueryProof<C: Config> {
    pub commit_phase_openings: Vec<FmtCommitPhaseProofStep<C>>,
    pub phantom: PhantomData<C>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
pub struct FmtCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Vec<Hash<C>>,
    pub phantom: PhantomData<C>,
}
