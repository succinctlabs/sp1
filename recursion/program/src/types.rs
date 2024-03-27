use p3_air::BaseAir;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::{
    air::MachineAir,
    stark::{AirOpenedValues, Chip, ChipOpenedValues, ShardCommitment},
};

use sp1_recursion_compiler::prelude::*;

use crate::fri::TwoAdicPcsProofVariable;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L54
#[allow(type_alias_bounds)]
pub type Commitment<C: Config> = Array<C, Felt<C::F>>;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/config.rs#L1
#[derive(DslVariable, Clone)]
pub struct FriConfigVariable<C: Config> {
    pub log_blowup: Var<C::N>,
    pub num_queries: Var<C::N>,
    pub proof_of_work_bits: Var<C::N>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(DslVariable, Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Array<C, Commitment<C>>,
    pub query_proofs: Array<C, FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Array<C, Commitment<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(DslVariable, Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Array<C, Var<C::N>>,
    pub betas: Array<C, Ext<C::F, C::EF>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/matrix/src/lib.rs#L38
#[derive(DslVariable, Clone)]
pub struct Dimensions<C: Config> {
    pub height: Var<C::N>,
}

pub struct ShardProofVariable<C: Config> {
    pub index: Usize<C::N>,
    pub commitment: ShardCommitment<Commitment<C>>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub sorted_indices: Vec<Var<C::N>>,
}

#[derive(DslVariable, Debug, Clone)]
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
    // pub fn from_constant(builder: &mut Builder<C>, opening: &ChipOpenedValues<C::EF>) -> Self {
    //     ChipOpening {
    //         preprocessed: builder.const_opened_values(&opening.preprocessed),
    //         main: builder.const_opened_values(&opening.main),
    //         permutation: builder.const_opened_values(&opening.permutation),
    //         quotient: opening
    //             .quotient
    //             .iter()
    //             .map(|q| q.iter().map(|s| builder.eval(s.cons())).collect())
    //             .collect(),
    //         cumulative_sum: builder.eval(opening.cumulative_sum.cons()),
    //         log_degree: builder.eval(opening.log_degree),
    //     }
    // }

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
