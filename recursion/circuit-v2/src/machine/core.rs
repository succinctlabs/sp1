use sp1_recursion_compiler::ir::{Config, Felt};

use crate::{
    challenger::DuplexChallengerVariable, stark::ShardProofVariable, VerifyingKeyVariable,
};

pub struct SP1RecursionWitnessVariable<C: Config> {
    pub vk: VerifyingKeyVariable<C>,
    pub shard_proofs: Vec<ShardProofVariable<C>>,
    pub leaf_challenger: DuplexChallengerVariable<C>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<C>,
    pub is_complete: Felt<C::F>,
}
