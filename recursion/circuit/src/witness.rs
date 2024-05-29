use p3_bn254_fr::Bn254Fr;
use sp1_core::stark::{
    AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, ShardProof,
};
use sp1_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Config, Ext, Felt, Var, Witness},
};
use sp1_recursion_core::stark::config::{
    BabyBearPoseidon2Outer, OuterBatchOpening, OuterChallenge, OuterCommitPhaseStep, OuterDigest,
    OuterFriProof, OuterPcsProof, OuterQueryProof, OuterVal,
};

use crate::types::{
    AirOpenedValuesVariable, BatchOpeningVariable, ChipOpenedValuesVariable,
    FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable, OuterDigestVariable,
    RecursionShardOpenedValuesVariable, RecursionShardProofVariable, TwoAdicPcsProofVariable,
};

pub trait Witnessable<C: Config> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut Witness<C>);
}

type C = OuterConfig;

impl Witnessable<C> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.vars.push(*self);
    }
}

impl Witnessable<C> for OuterVal {
    type WitnessVariable = Felt<OuterVal>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_felt()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.felts.push(*self);
    }
}

impl Witnessable<C> for OuterChallenge {
    type WitnessVariable = Ext<OuterVal, OuterChallenge>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_ext()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.exts.push(*self);
    }
}

trait VectorWitnessable<C: Config>: Witnessable<C> {}
impl VectorWitnessable<C> for Bn254Fr {}
impl VectorWitnessable<C> for OuterVal {}
impl VectorWitnessable<C> for OuterChallenge {}
impl VectorWitnessable<C> for Vec<OuterVal> {}
impl VectorWitnessable<C> for Vec<OuterChallenge> {}
impl VectorWitnessable<C> for Vec<Vec<OuterVal>> {}

impl<I: VectorWitnessable<C>> Witnessable<C> for Vec<I> {
    type WitnessVariable = Vec<I::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.iter().for_each(|x| x.write(witness));
    }
}

impl Witnessable<C> for OuterDigest {
    type WitnessVariable = OuterDigestVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        [builder.witness_var()]
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.vars.push(self[0]);
    }
}
impl VectorWitnessable<C> for OuterDigest {}

impl Witnessable<C> for ShardCommitment<OuterDigest> {
    type WitnessVariable = ShardCommitment<OuterDigestVariable<C>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commit = self.main_commit.read(builder);
        let permutation_commit = self.permutation_commit.read(builder);
        let quotient_commit = self.quotient_commit.read(builder);
        ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.main_commit.write(witness);
        self.permutation_commit.write(witness);
        self.quotient_commit.write(witness);
    }
}

impl Witnessable<C> for AirOpenedValues<OuterChallenge> {
    type WitnessVariable = AirOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let next = self.next.read(builder);
        AirOpenedValuesVariable { local, next }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.local.write(witness);
        self.next.write(witness);
    }
}

impl Witnessable<C> for ChipOpenedValues<OuterChallenge> {
    type WitnessVariable = ChipOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let permutation = self.permutation.read(builder);
        let quotient = self.quotient.read(builder);
        let cumulative_sum = self.cumulative_sum.read(builder);
        let log_degree = self.log_degree;
        ChipOpenedValuesVariable {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum,
            log_degree,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.preprocessed.write(witness);
        self.main.write(witness);
        self.permutation.write(witness);
        self.quotient.write(witness);
        self.cumulative_sum.write(witness);
    }
}
impl VectorWitnessable<C> for ChipOpenedValues<OuterChallenge> {}

impl Witnessable<C> for ShardOpenedValues<OuterChallenge> {
    type WitnessVariable = RecursionShardOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chips = self.chips.read(builder);
        RecursionShardOpenedValuesVariable { chips }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.chips.write(witness);
    }
}

impl Witnessable<C> for OuterBatchOpening {
    type WitnessVariable = BatchOpeningVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        BatchOpeningVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}
impl VectorWitnessable<C> for OuterBatchOpening {}
impl VectorWitnessable<C> for Vec<OuterBatchOpening> {}

impl Witnessable<C> for OuterCommitPhaseStep {
    type WitnessVariable = FriCommitPhaseProofStepVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        FriCommitPhaseProofStepVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.sibling_value.write(witness);
        self.opening_proof.write(witness);
    }
}
impl VectorWitnessable<C> for OuterCommitPhaseStep {}

impl Witnessable<C> for OuterQueryProof {
    type WitnessVariable = FriQueryProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        FriQueryProofVariable {
            commit_phase_openings,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.commit_phase_openings.write(witness);
    }
}
impl VectorWitnessable<C> for OuterQueryProof {}

impl Witnessable<C> for OuterFriProof {
    type WitnessVariable = FriProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: OuterDigest = (*commit).into();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.commit_phase_commits.iter().for_each(|commit| {
            let commit: OuterDigest = (*commit).into();
            commit.write(witness)
        });
        self.query_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}

impl Witnessable<C> for OuterPcsProof {
    type WitnessVariable = TwoAdicPcsProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let fri_proof = self.fri_proof.read(builder);
        let query_openings = self.query_openings.read(builder);
        TwoAdicPcsProofVariable {
            fri_proof,
            query_openings,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.fri_proof.write(witness);
        self.query_openings.write(witness);
    }
}

impl Witnessable<C> for ShardProof<BabyBearPoseidon2Outer> {
    type WitnessVariable = RecursionShardProofVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commit: OuterDigest = self.commitment.main_commit.into();
        let permutation_commit: OuterDigest = self.commitment.permutation_commit.into();
        let quotient_commit: OuterDigest = self.commitment.quotient_commit.into();
        let commitment = ShardCommitment {
            main_commit: main_commit.read(builder),
            permutation_commit: permutation_commit.read(builder),
            quotient_commit: quotient_commit.read(builder),
        };
        let opened_values = self.opened_values.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        let public_values = self.public_values.read(builder);
        let public_values = builder.vec(public_values);

        RecursionShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        let main_commit: OuterDigest = self.commitment.main_commit.into();
        let permutation_commit: OuterDigest = self.commitment.permutation_commit.into();
        let quotient_commit: OuterDigest = self.commitment.quotient_commit.into();
        main_commit.write(witness);
        permutation_commit.write(witness);
        quotient_commit.write(witness);
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
        self.public_values.write(witness);
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_field::AbstractField;
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, ExtConst, Witness},
    };
    use sp1_recursion_core::stark::config::OuterChallenge;
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;

    #[test]
    fn test_witness_simple() {
        let mut builder = Builder::<OuterConfig>::default();
        let a = builder.witness_var();
        let b = builder.witness_var();
        builder.assert_var_eq(a, Bn254Fr::one());
        builder.assert_var_eq(b, Bn254Fr::two());
        builder.print_v(a);
        builder.print_v(b);

        let a = builder.witness_felt();
        let b = builder.witness_felt();
        builder.assert_felt_eq(a, BabyBear::one());
        builder.assert_felt_eq(b, BabyBear::two());
        builder.print_f(a);
        builder.print_f(b);

        let a = builder.witness_ext();
        let b = builder.witness_ext();
        builder.assert_ext_eq(a, OuterChallenge::one().cons());
        builder.assert_ext_eq(b, OuterChallenge::two().cons());
        builder.print_e(a);
        builder.print_e(b);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(
            constraints,
            Witness {
                vars: vec![Bn254Fr::one(), Bn254Fr::two()],
                felts: vec![BabyBear::one(), BabyBear::two()],
                exts: vec![OuterChallenge::one(), OuterChallenge::two()],
                vkey_hash: Bn254Fr::one(),
                commited_values_digest: Bn254Fr::one(),
            },
        );
    }
}
