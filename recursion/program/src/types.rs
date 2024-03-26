use sp1_core::stark::{AirOpenedValues, ChipOpenedValues, ShardCommitment};
use sp1_recursion_compiler::{
    ir::{Builder, Config, Ext, ExtConst, Usize},
    verifier::fri::{types::Commitment, TwoAdicPcsProofVariable},
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

#[derive(Debug, Clone)]
pub struct ChipOpening<C: Config> {
    pub preprocessed: AirOpenedValues<Ext<C::F, C::EF>>,
    pub main: AirOpenedValues<Ext<C::F, C::EF>>,
    pub permutation: AirOpenedValues<Ext<C::F, C::EF>>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: Usize<C::N>,
}

impl<C: Config> ChipOpening<C> {
    pub fn from_constant(builder: &mut Builder<C>, opening: &ChipOpenedValues<C::EF>) -> Self {
        ChipOpening {
            preprocessed: builder.const_opened_values(&opening.preprocessed),
            main: builder.const_opened_values(&opening.main),
            permutation: builder.const_opened_values(&opening.permutation),
            quotient: opening
                .quotient
                .iter()
                .map(|q| q.iter().map(|s| builder.eval(s.cons())).collect())
                .collect(),
            cumulative_sum: builder.eval(opening.cumulative_sum.cons()),
            log_degree: builder.eval(opening.log_degree),
        }
    }
}
