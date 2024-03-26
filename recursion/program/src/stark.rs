use p3_air::Air;
use sp1_core::stark::{MachineChip, StarkGenericConfig, VerifierConstraintFolder};
use sp1_recursion_compiler::{
    ir::{Builder, Config},
    verifier::challenger::DuplexChallengerVariable,
};

use crate::types::ShardProofVariable;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

impl<C: Config, SC: StarkGenericConfig> StarkVerifier<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn verify_shard<A>(
        &mut self,
        chips: &[&MachineChip<SC, A>],
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
    ) where
        A: for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    {
        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            ..
        } = proof;
    }
}
