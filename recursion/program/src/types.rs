use p3_air::BaseAir;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::{
    air::MachineAir,
    stark::{AirOpenedValues, Chip, ChipOpenedValues, ShardCommitment},
};
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
    pub local: Array<C, Ext<C::F, C::EF>>,
    pub next: Array<C, Ext<C::F, C::EF>>,
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

    pub fn from_variable<A>(
        builder: &mut Builder<C>,
        chip: &Chip<C::F, A>,
        opening: &ChipOpenedValuesVariable<C>,
    ) -> Self
    where
        A: MachineAir<C::F>,
    {
        let mut preprocessed = AirOpenedValues {
            local: vec![],
            next: vec![],
        };
        let preprocess_width = chip.preprocessed_width();
        for i in 0..preprocess_width {
            preprocessed
                .local
                .push(builder.get(&opening.preprocessed.local, i));
            preprocessed
                .next
                .push(builder.get(&opening.preprocessed.next, i));
        }

        let mut main = AirOpenedValues {
            local: vec![],
            next: vec![],
        };
        let main_width = chip.width();
        for i in 0..main_width {
            main.local.push(builder.get(&opening.main.local, i));
            main.next.push(builder.get(&opening.main.next, i));
        }

        let mut permutation = AirOpenedValues {
            local: vec![],
            next: vec![],
        };
        let permutation_width = C::EF::D * (chip.num_interactions() + 1);
        for i in 0..permutation_width {
            permutation
                .local
                .push(builder.get(&opening.permutation.local, i));
            permutation
                .next
                .push(builder.get(&opening.permutation.next, i));
        }

        let num_quotient_chunks = 1 << chip.log_quotient_degree();

        let mut quotient = vec![];
        for i in 0..num_quotient_chunks {
            let chunk = builder.get(&opening.quotient, i);
            let mut quotient_vals = vec![];
            for j in 0..C::EF::D {
                let value = builder.get(&chunk, j);
                quotient_vals.push(value);
            }
            quotient.push(quotient_vals);
        }

        ChipOpening {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum: opening.cumulative_sum,
            log_degree: Usize::Var(opening.log_degree),
        }
    }
}

impl<C: Config> FromConstant<C> for AirOpenedValuesVariable<C> {
    type Constant = AirOpenedValues<C::EF>;

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        AirOpenedValuesVariable {
            local: builder.eval_const(value.local),
            next: builder.eval_const(value.next),
        }
    }
}

impl<C: Config> FromConstant<C> for ChipOpenedValuesVariable<C> {
    type Constant = ChipOpenedValues<C::EF>;

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed: builder.eval_const(value.preprocessed),
            main: builder.eval_const(value.main),
            permutation: builder.eval_const(value.permutation),
            quotient: builder.eval_const(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_degree: builder.eval(C::N::from_canonical_usize(value.log_degree)),
        }
    }
}
