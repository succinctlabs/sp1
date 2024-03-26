use sp1_core::stark::ShardCommitment;
use sp1_recursion_compiler::{
    ir::{Config, Usize},
    verifier::{
        fri::{types::Commitment, TwoAdicPcsProofVariable},
        ChipOpening,
    },
};

pub struct ShardProofVariable<C: Config> {
    pub index: Usize<C::N>,
    pub commitment: ShardCommitment<Commitment<C>>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
}

#[derive(Debug, Clone)]
pub struct ShardOpenedValuesVariable<C: Config> {
    pub chips: Vec<ChipOpening<C>>,
}
