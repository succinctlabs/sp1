use p3_air::BaseAir;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractExtensionField;
use sp1_core::{
    air::MachineAir,
    stark::{AirOpenedValues, Chip, ChipOpenedValues, ShardCommitment},
};
use sp1_recursion_compiler::ir::{Array, Builder, Config, Ext, ExtConst, Felt, FromConstant, Var};

use crate::DIGEST_SIZE;

pub type OuterDigestVariable<C: Config> = [Var<C::N>; DIGEST_SIZE];

pub struct RecursionShardProofVariable<C: Config> {
    pub commitment: ShardCommitment<OuterDigestVariable<C>>,
    pub opened_values: RecursionShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub public_values: Array<C, Felt<C::F>>,
}

#[derive(Clone)]
pub struct RecursionShardOpenedValuesVariable<C: Config> {
    pub chips: Vec<ChipOpenedValuesVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Vec<OuterDigestVariable<C>>,
    pub query_proofs: Vec<FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<OuterDigestVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Vec<Var<C::N>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    pub opening_proof: Vec<OuterDigestVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Vec<Vec<BatchOpeningVariable<C>>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: OuterDigestVariable<C>,
    pub mats: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

#[derive(Debug, Clone)]
pub struct ChipOpenedValuesVariable<C: Config> {
    pub preprocessed: AirOpenedValuesVariable<C>,
    pub main: AirOpenedValuesVariable<C>,
    pub permutation: AirOpenedValuesVariable<C>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: usize,
}

#[derive(Debug, Clone)]
pub struct AirOpenedValuesVariable<C: Config> {
    pub local: Vec<Ext<C::F, C::EF>>,
    pub next: Vec<Ext<C::F, C::EF>>,
}

impl<C: Config> FromConstant<C> for AirOpenedValuesVariable<C> {
    type Constant = AirOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        AirOpenedValuesVariable {
            local: value.local.iter().map(|x| builder.constant(*x)).collect(),
            next: value.next.iter().map(|x| builder.constant(*x)).collect(),
        }
    }
}

impl<C: Config> FromConstant<C> for ChipOpenedValuesVariable<C> {
    type Constant = ChipOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed: builder.constant(value.preprocessed),
            main: builder.constant(value.main),
            permutation: builder.constant(value.permutation),
            quotient: value
                .quotient
                .iter()
                .map(|x| x.iter().map(|y| builder.constant(*y)).collect())
                .collect(),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_degree: value.log_degree,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChipOpening<C: Config> {
    pub preprocessed: AirOpenedValues<Ext<C::F, C::EF>>,
    pub main: AirOpenedValues<Ext<C::F, C::EF>>,
    pub permutation: AirOpenedValues<Ext<C::F, C::EF>>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: usize,
}

impl<C: Config> ChipOpening<C> {
    pub fn from_variable<A>(
        _: &mut Builder<C>,
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
            preprocessed.local.push(opening.preprocessed.local[i]);
            preprocessed.next.push(opening.preprocessed.next[i]);
        }

        let mut main = AirOpenedValues {
            local: vec![],
            next: vec![],
        };
        let main_width = chip.width();
        for i in 0..main_width {
            main.local.push(opening.main.local[i]);
            main.next.push(opening.main.next[i]);
        }

        let mut permutation = AirOpenedValues {
            local: vec![],
            next: vec![],
        };
        let permutation_width = C::EF::D * chip.permutation_width();

        for i in 0..permutation_width {
            permutation.local.push(opening.permutation.local[i]);
            permutation.next.push(opening.permutation.next[i]);
        }

        let num_quotient_chunks = 1 << chip.log_quotient_degree();

        let mut quotient = vec![];
        for i in 0..num_quotient_chunks {
            let chunk = &opening.quotient[i];
            let mut quotient_vals = vec![];
            for j in 0..C::EF::D {
                let value = &chunk[j];
                quotient_vals.push(*value);
            }
            quotient.push(quotient_vals);
        }

        ChipOpening {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum: opening.cumulative_sum,
            log_degree: opening.log_degree,
        }
    }
}
