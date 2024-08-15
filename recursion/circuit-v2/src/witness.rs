use std::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_field::AbstractExtensionField;

use p3_fri::{CommitPhaseProofStep, QueryProof};
use sp1_core::{
    stark::{AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, ShardProof},
    utils::{
        BabyBearPoseidon2, InnerBatchOpening, InnerChallenge, InnerChallengeMmcs, InnerDigest,
        InnerFriProof, InnerPcsProof, InnerVal,
    },
};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Ext, Felt},
};
use sp1_recursion_core_v2::air::Block;

use crate::{
    stark::ShardProofVariable, BatchOpeningVariable, CircuitConfig,
    FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable,
    TwoAdicPcsProofVariable,
};

pub type Witness<C> = Block<<C as Config>::F>;

/// TODO change the name. For now, the name is unique to prevent confusion.
pub trait Witnessable<C: Config> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self) -> Vec<Witness<C>>;
}

impl<'a, C: Config, T: Witnessable<C>> Witnessable<C> for &'a T {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        (*self).read(builder)
    }

    fn write(&self) -> Vec<Witness<C>> {
        (*self).write()
    }
}

// TODO Bn254Fr

impl<C: Config<F = InnerVal>> Witnessable<C> for InnerVal {
    type WitnessVariable = Felt<InnerVal>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.hint_felt_v2()
    }

    fn write(&self) -> Vec<Witness<C>> {
        vec![Block::from(*self)]
    }
}

impl<C: Config<F = InnerVal, EF = InnerChallenge>> Witnessable<C> for InnerChallenge {
    type WitnessVariable = Ext<InnerVal, InnerChallenge>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.hint_ext_v2()
    }

    fn write(&self) -> Vec<Witness<C>> {
        vec![Block::from(self.as_base_slice())]
    }
}

impl<C: Config, T: Witnessable<C>, const N: usize> Witnessable<C> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter()
            .map(|x| x.read(builder))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|x: Vec<_>| {
                // Cannot just `.unwrap()` without requiring Debug bounds.
                panic!(
                    "could not coerce vec of len {} into array of len {N}",
                    x.len()
                )
            })
    }

    fn write(&self) -> Vec<Witness<C>> {
        self.iter().flat_map(|x| x.write()).collect()
    }
}

impl<C: Config, T: Witnessable<C>> Witnessable<C> for Vec<T> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self) -> Vec<Witness<C>> {
        self.iter().flat_map(|x| x.write()).collect()
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for ShardProof<BabyBearPoseidon2>
{
    type WitnessVariable = ShardProofVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commitment = self.commitment.read(builder);
        let opened_values = self.opened_values.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        let public_values = self.public_values.read(builder);
        let chip_ordering = self.chip_ordering.clone();

        ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
            chip_ordering,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.commitment),
            Witnessable::<C>::write(&self.opened_values),
            Witnessable::<C>::write(&self.opening_proof),
            Witnessable::<C>::write(&self.public_values),
        ]
        .concat()
    }
}

impl<C: Config, T: Witnessable<C>> Witnessable<C> for ShardCommitment<T> {
    type WitnessVariable = ShardCommitment<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commit = self.main_commit.read(builder);
        let permutation_commit = self.permutation_commit.read(builder);
        let quotient_commit = self.quotient_commit.read(builder);
        Self::WitnessVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.main_commit),
            Witnessable::<C>::write(&self.permutation_commit),
            Witnessable::<C>::write(&self.quotient_commit),
        ]
        .concat()
    }
}

impl<C: Config<F = InnerVal, EF = InnerChallenge>> Witnessable<C>
    for ShardOpenedValues<InnerChallenge>
{
    type WitnessVariable = ShardOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chips = self.chips.read(builder);
        Self::WitnessVariable { chips }
    }

    fn write(&self) -> Vec<Witness<C>> {
        Witnessable::<C>::write(&self.chips)
    }
}

impl<C: Config<F = InnerVal, EF = InnerChallenge>> Witnessable<C>
    for ChipOpenedValues<InnerChallenge>
{
    type WitnessVariable = ChipOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let permutation = self.permutation.read(builder);
        let quotient = self.quotient.read(builder);
        let cumulative_sum = self.cumulative_sum.read(builder);
        let log_degree = self.log_degree;
        Self::WitnessVariable {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum,
            log_degree,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.preprocessed),
            Witnessable::<C>::write(&self.main),
            Witnessable::<C>::write(&self.permutation),
            Witnessable::<C>::write(&self.quotient),
            Witnessable::<C>::write(&self.cumulative_sum),
        ]
        .concat()
    }
}

impl<C: Config<F = InnerVal, EF = InnerChallenge>> Witnessable<C>
    for AirOpenedValues<InnerChallenge>
{
    type WitnessVariable = AirOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let next = self.next.read(builder);
        Self::WitnessVariable { local, next }
    }

    fn write(&self) -> Vec<Witness<C>> {
        let mut stream = Vec::new();
        stream.extend(Witnessable::<C>::write(&self.local));
        stream.extend(Witnessable::<C>::write(&self.next));
        stream
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for InnerPcsProof
{
    type WitnessVariable = TwoAdicPcsProofVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let fri_proof = self.fri_proof.read(builder);
        let query_openings = self.query_openings.read(builder);
        Self::WitnessVariable {
            fri_proof,
            query_openings,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.fri_proof),
            Witnessable::<C>::write(&self.query_openings),
        ]
        .concat()
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for InnerBatchOpening
{
    type WitnessVariable = BatchOpeningVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.opened_values),
            Witnessable::<C>::write(&self.opening_proof),
        ]
        .concat()
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for InnerFriProof
{
    type WitnessVariable = FriProofVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: &InnerDigest = commit.borrow();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        Self::WitnessVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            self.commit_phase_commits
                .iter()
                .flat_map(|commit| {
                    let commit = Borrow::<InnerDigest>::borrow(commit);
                    Witnessable::<C>::write(commit)
                })
                .collect(),
            Witnessable::<C>::write(&self.query_proofs),
            Witnessable::<C>::write(&self.final_poly),
            Witnessable::<C>::write(&self.pow_witness),
        ]
        .concat()
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for QueryProof<InnerChallenge, InnerChallengeMmcs>
{
    type WitnessVariable = FriQueryProofVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        Self::WitnessVariable {
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        Witnessable::<C>::write(&self.commit_phase_openings)
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<BabyBear>>> Witnessable<C>
    for CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs>
{
    type WitnessVariable = FriCommitPhaseProofStepVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Witnessable::<C>::write(&self.sibling_value),
            Witnessable::<C>::write(&self.opening_proof),
        ]
        .concat()
    }
}
