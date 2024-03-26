use p3_air::Air;
use sp1_core::stark::{AirOpenedValues, ChipOpenedValues, ShardCommitment};
use sp1_recursion_compiler::{
    ir::{Array, Builder, Config, Ext, ExtConst, Usize},
    verifier::fri::{types::Commitment, TwoAdicPcsProofVariable},
};

use sp1_recursion_compiler::prelude::*;

pub struct ShardProofVariable<C: Config> {
    pub index: Usize<C::N>,
    pub commitment: ShardCommitment<Commitment<C>>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
}

#[derive(Debug, Clone)]
pub struct ShardOpenedValuesVariable<C: Config> {
    pub chips: Array<C, ChipOpenedValuesVariable<C>>,
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

#[derive(DslVariable, Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct ChipOpenedValuesVariable<C: Config> {
    pub preprocessed: AirOpenedValuesVariable<C>,
    pub main: AirOpenedValuesVariable<C>,
    pub permutation: AirOpenedValuesVariable<C>,
    pub quotient: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: Var<C::N>,
}

#[derive(DslVariable, Debug, Clone)]
pub struct AirOpenedValuesVariable<C: Config> {
    local: Array<C, Ext<C::F, C::EF>>,
    next: Array<C, Ext<C::F, C::EF>>,
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

// impl<C: Config> AirOpenedValuesVariable<C> {
//     pub fn assign_constant(
//         &self,
//         builder: &mut Builder<C>,
//         opened_values: &AirOpenedValues<C::EF>,
//     ) -> AirOpenedValues<Ext<C::F, C::EF>> {
//         AirOpenedValues::<Ext<C::F, C::EF>> {
//             local: opened_values
//                 .local
//                 .iter()
//                 .map(|s| builder.eval(SymbolicExt::Const(*s)))
//                 .collect(),
//             next: opened_values
//                 .next
//                 .iter()
//                 .map(|s| builder.eval(SymbolicExt::Const(*s)))
//                 .collect(),
//         }
//     }
// }

// impl<C: Config> ChipOpenedValuesVariable<C> {
//     pub fn assign_constant(
//         &self,
//         builder: &mut Builder<C>,
//         opening: &ChipOpenedValues<C::EF>,
//     ) -> Self {
//         ChipOpening {
//             preprocessed: builder.const_opened_values(&opening.preprocessed),
//             main: builder.const_opened_values(&opening.main),
//             permutation: builder.const_opened_values(&opening.permutation),
//             quotient: opening
//                 .quotient
//                 .iter()
//                 .map(|q| q.iter().map(|s| builder.eval(s.cons())).collect())
//                 .collect(),
//             cumulative_sum: builder.eval(opening.cumulative_sum.cons()),
//             log_degree: builder.eval(opening.log_degree),
//         }
//     }
// }
