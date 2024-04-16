use p3_air::BaseAir;
use p3_field::{AbstractExtensionField, AbstractField};
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    stark::{AirOpenedValues, Chip, ChipOpenedValues, ShardProof, StarkGenericConfig},
};
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::DIGEST_SIZE;

use crate::fri::types::TwoAdicPcsProofVariable;
use crate::fri::types::{DigestVariable, FriConfigVariable};
use crate::fri::TwoAdicMultiplicativeCosetVariable;

#[derive(Serialize, Deserialize)]
pub struct ReduceProofPublicValues<SC: StarkGenericConfig> {
    pub start_pc: SC::Val,
    pub next_pc: SC::Val,
    pub start_shard: SC::Val,
    pub next_shard: SC::Val,
    pub exit_code: SC::Val,
}

#[derive(DslVariable, Clone)]
pub struct ReduceProofPublicValuesVariable<C: Config> {
    pub start_pc: Felt<C::F>,
    pub next_pc: Felt<C::F>,
    pub start_shard: Felt<C::F>,
    pub next_shard: Felt<C::F>,
    pub exit_code: Felt<C::F>,
}

impl<C: Config> ReduceProofPublicValuesVariable<C> {
    pub fn to_array(&self, builder: &mut Builder<C>) -> Array<C, Felt<C::F>> {
        let mut array = builder.array(4);
        builder.set(&mut array, 0, self.start_pc);
        builder.set(&mut array, 1, self.start_shard);
        builder.set(&mut array, 2, self.next_pc);
        builder.set(&mut array, 3, self.next_shard);
        array
    }

    pub fn verify_digest(
        &self,
        builder: &mut Builder<C>,
        expected_digest: [Felt<C::F>; DIGEST_SIZE],
    ) {
        let elt_array = self.to_array(builder);
        let pv_digest = builder.poseidon2_hash(&elt_array);

        for (j, expected_digest_elt) in expected_digest.iter().enumerate().take(DIGEST_SIZE) {
            let digest_element = builder.get(&pv_digest, j);
            builder.assert_felt_eq(*expected_digest_elt, digest_element);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>"))]
pub struct ReduceProof<SC: StarkGenericConfig> {
    pub shard_proof: ShardProof<SC>,
    pub public_values: ReduceProofPublicValues<SC>,
}

impl<SC: StarkGenericConfig> From<ShardProof<SC>> for ReduceProof<SC> {
    fn from(shard_proof: ShardProof<SC>) -> Self {
        let pv =
            PublicValues::<Word<SC::Val>, SC::Val>::from_vec(shard_proof.public_values.clone());

        ReduceProof {
            shard_proof,
            public_values: ReduceProofPublicValues {
                start_pc: pv.start_pc,
                next_pc: pv.next_pc,
                start_shard: pv.shard,
                next_shard: if pv.next_pc == SC::Val::zero() {
                    SC::Val::zero()
                } else {
                    pv.shard + SC::Val::one()
                },
                exit_code: pv.exit_code,
            },
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct ReduceProofVariable<C: Config> {
    pub shard_proof: ShardProofVariable<C>,
    pub public_values: ReduceProofPublicValuesVariable<C>,
}

impl<C: Config> ReduceProofVariable<C> {
    pub fn get_expected_pv_digest(&self, builder: &mut Builder<C>) -> [Felt<C::F>; DIGEST_SIZE] {
        let mut expected_digest = Vec::new();

        for i in 0..DIGEST_SIZE {
            expected_digest.push(builder.get(&self.shard_proof.public_values, i));
        }

        expected_digest.try_into().unwrap()
    }
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(DslVariable, Clone)]
pub struct ShardProofVariable<C: Config> {
    pub index: Var<C::N>,
    pub commitment: ShardCommitmentVariable<C>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub public_values: Array<C, Felt<C::F>>,
}

/// Reference: https://github.com/succinctlabs/sp1/blob/b5d5473c010ab0630102652146e16c014a1eddf6/core/src/stark/machine.rs#L63
#[derive(DslVariable, Clone)]
pub struct VerifyingKeyVariable<C: Config> {
    pub commitment: DigestVariable<C>,
}

#[derive(DslVariable, Clone)]
pub struct ShardCommitmentVariable<C: Config> {
    pub main_commit: DigestVariable<C>,
    pub permutation_commit: DigestVariable<C>,
    pub quotient_commit: DigestVariable<C>,
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
    pub log_degree: Var<C::N>,
}

#[derive(DslVariable, Debug, Clone)]
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

        let preprocessed_width = chip.preprocessed_width();
        for i in 0..preprocessed_width {
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
        let permutation_width =
            C::EF::D * ((chip.num_interactions() + 1) / chip.logup_batch_size() + 1);
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
            log_degree: opening.log_degree,
        }
    }
}

impl<C: Config> FromConstant<C> for AirOpenedValuesVariable<C> {
    type Constant = AirOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        AirOpenedValuesVariable {
            local: builder.constant(value.local),
            next: builder.constant(value.next),
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
            quotient: builder.constant(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_degree: builder.eval(C::N::from_canonical_usize(value.log_degree)),
        }
    }
}

impl<C: Config> FriConfigVariable<C> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<C>,
        log_degree: impl Into<Usize<C::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<C> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<C>,
        bits: impl Into<Usize<C::N>>,
    ) -> Felt<C::F> {
        builder.get(&self.generators, bits)
    }
}
