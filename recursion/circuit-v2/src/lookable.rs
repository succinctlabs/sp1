use p3_field::AbstractExtensionField;

use p3_fri::{CommitPhaseProofStep, QueryProof};
use sp1_core::{
    air::MachineAir,
    stark::{
        AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, StarkGenericConfig,
    },
    utils::{
        BabyBearPoseidon2, InnerBatchOpening, InnerChallenge, InnerChallengeMmcs, InnerDigest,
        InnerDigestHash, InnerFriProof, InnerPcsProof, InnerVal,
    },
};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    config::InnerConfig,
    ir::{Builder, Config, Ext, Felt},
};
use sp1_recursion_core::air::Block;

use crate::{
    stark::{
        AirOpenedValuesVariable, ChipOpenedValuesVariable, ShardCommitmentVariable,
        ShardOpenedValuesVariable, ShardProofHint, ShardProofVariable,
    },
    BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable,
    TwoAdicPcsProofVariable,
};

pub type Witness<C> = Block<<C as Config>::F>;

/// TODO change the name. For now, the name is unique to prevent confusion.
pub trait Lookable<C: Config> {
    type LookVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable;

    fn write(&self) -> Vec<Witness<C>>;
}

impl<'a, C: Config, T: Lookable<C>> Lookable<C> for &'a T {
    type LookVariable = T::LookVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        (*self).read(builder)
    }

    fn write(&self) -> Vec<Witness<C>> {
        (*self).write()
    }
}

// TODO Bn254Fr

impl<C: Config<F = InnerVal>> Lookable<C> for InnerVal {
    type LookVariable = Felt<InnerVal>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        builder.hint_felt_v2()
    }

    fn write(&self) -> Vec<Witness<C>> {
        vec![Block::from(*self)]
    }
}

impl<C: Config<F = InnerVal, EF = InnerChallenge>> Lookable<C> for InnerChallenge {
    type LookVariable = Ext<InnerVal, InnerChallenge>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        builder.hint_ext_v2()
    }

    fn write(&self) -> Vec<Witness<C>> {
        vec![Block::from(self.as_base_slice())]
    }
}

impl<C: Config, T: Lookable<C>, const N: usize> Lookable<C> for [T; N] {
    type LookVariable = [T::LookVariable; N];

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
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

impl<C: Config, T: Lookable<C>> Lookable<C> for Vec<T> {
    type LookVariable = Vec<T::LookVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self) -> Vec<Witness<C>> {
        self.iter().flat_map(|x| x.write()).collect()
    }
}

type C = InnerConfig;

impl<'a, SC, A> Lookable<C> for ShardProofHint<'a, SC, A>
where
    SC: StarkGenericConfig<
        Pcs = <BabyBearPoseidon2 as StarkGenericConfig>::Pcs,
        Challenge = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
        Challenger = <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
    >,
    ShardCommitment<sp1_core::stark::Com<SC>>: Lookable<C>,
    A: MachineAir<<SC as StarkGenericConfig>::Val>,
{
    type LookVariable = ShardProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let commitment = self.proof.commitment.read(builder);
        let opened_values = self.proof.opened_values.read(builder);
        let opening_proof = self.proof.opening_proof.read(builder);
        let public_values = self.proof.public_values.read(builder);
        // Hopefully these clones are cheap...
        let quotient_data = self.quotient_data.clone();
        let sorted_idxs = self.sorted_idxs.clone();
        ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
            quotient_data,
            sorted_idxs,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            self.proof.commitment.write(),
            self.proof.opened_values.write(),
            self.proof.opening_proof.write(),
            Lookable::<C>::write(&self.proof.public_values),
        ]
        .concat()
    }
}

impl Lookable<C> for ShardCommitment<InnerDigestHash> {
    type LookVariable = ShardCommitmentVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let main_commit = InnerDigest::from(self.main_commit).read(builder);
        let permutation_commit = InnerDigest::from(self.permutation_commit).read(builder);
        let quotient_commit = InnerDigest::from(self.quotient_commit).read(builder);
        Self::LookVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Lookable::<C>::write(&InnerDigest::from(self.main_commit)),
            Lookable::<C>::write(&InnerDigest::from(self.permutation_commit)),
            Lookable::<C>::write(&InnerDigest::from(self.quotient_commit)),
        ]
        .concat()
    }
}

impl Lookable<C> for ShardOpenedValues<InnerChallenge> {
    type LookVariable = ShardOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let chips = self.chips.read(builder);
        Self::LookVariable { chips }
    }

    fn write(&self) -> Vec<Witness<C>> {
        self.chips.write()
    }
}

impl Lookable<C> for ChipOpenedValues<InnerChallenge> {
    type LookVariable = ChipOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let permutation = self.permutation.read(builder);
        let quotient = self.quotient.read(builder);
        let cumulative_sum = self.cumulative_sum.read(builder);
        let log_degree = self.log_degree;
        Self::LookVariable {
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
            self.preprocessed.write(),
            self.main.write(),
            self.permutation.write(),
            Lookable::<C>::write(&self.quotient),
            Lookable::<C>::write(&self.cumulative_sum),
        ]
        .concat()
    }
}

impl Lookable<C> for AirOpenedValues<InnerChallenge> {
    type LookVariable = AirOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let local = self.local.read(builder);
        let next = self.next.read(builder);
        Self::LookVariable { local, next }
    }

    fn write(&self) -> Vec<Witness<C>> {
        let mut stream = Vec::new();
        stream.extend(Lookable::<C>::write(&self.local));
        stream.extend(Lookable::<C>::write(&self.next));
        stream
    }
}

impl Lookable<C> for InnerPcsProof {
    type LookVariable = TwoAdicPcsProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let fri_proof = self.fri_proof.read(builder);
        let query_openings = self.query_openings.read(builder);
        Self::LookVariable {
            fri_proof,
            query_openings,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [self.fri_proof.write(), self.query_openings.write()].concat()
    }
}

impl Lookable<C> for InnerBatchOpening {
    type LookVariable = BatchOpeningVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::LookVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Lookable::<C>::write(&self.opened_values),
            Lookable::<C>::write(&self.opening_proof),
        ]
        .concat()
    }
}

impl Lookable<C> for InnerFriProof {
    type LookVariable = FriProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: InnerDigest = (*commit).into();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        Self::LookVariable {
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
                    let commit: InnerDigest = (*commit).into();
                    Lookable::<C>::write(&commit)
                })
                .collect(),
            self.query_proofs.write(),
            Lookable::<C>::write(&self.final_poly),
            Lookable::<C>::write(&self.pow_witness),
        ]
        .concat()
    }
}

impl Lookable<C> for QueryProof<InnerChallenge, InnerChallengeMmcs> {
    type LookVariable = FriQueryProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        Self::LookVariable {
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        self.commit_phase_openings.write()
    }
}

impl Lookable<C> for CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs> {
    type LookVariable = FriCommitPhaseProofStepVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::LookVariable {
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::LookVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Witness<C>> {
        [
            Lookable::<C>::write(&self.sibling_value),
            Lookable::<C>::write(&self.opening_proof),
        ]
        .concat()
    }
}
