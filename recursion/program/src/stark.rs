use itertools::{izip, Itertools};
use p3_air::Air;
use p3_field::TwoAdicField;
use sp1_core::stark::{MachineChip, ShardCommitment, StarkGenericConfig, VerifierConstraintFolder};
use sp1_recursion_compiler::{
    ir::{Builder, Config},
    verifier::challenger::DuplexChallengerVariable,
};

use crate::{commit::PcsVariable, fri::TwoAdicFriPcsVariable, types::ShardProofVariable};

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

impl<C: Config, SC: StarkGenericConfig> StarkVerifier<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
{
    pub fn verify_shard<A>(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        chips: &[&MachineChip<SC, A>],
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
    ) where
        A: for<'b> Air<VerifierConstraintFolder<'b, SC>>,
        C::F: TwoAdicField,
        C::EF: TwoAdicField,
    {
        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            ..
        } = proof;

        let log_degrees = opened_values
            .chips
            .iter()
            .map(|val| val.log_degree)
            .collect::<Vec<_>>();

        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.log_quotient_degree())
            .collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_log_degree(builder, *log_degree))
            .collect::<Vec<_>>();

        let ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe_commitment(builder, permutation_commit.clone());

        let alpha = challenger.sample_ext(builder);

        challenger.observe_commitment(builder, quotient_commit.clone());

        let zeta = challenger.sample_ext(builder);

        // let quotient_chunk_domains = trace_domains
        //     .iter()
        //     .zip_eq(log_degrees)
        //     .zip_eq(log_quotient_degrees)
        //     .map(|((domain, log_degree), log_quotient_degree)| {
        //         let quotient_degree = 1 << log_quotient_degree;
        //         let quotient_domain =
        //             domain.create_disjoint_domain(log_degree + log_quotient_degree);
        //         quotient_domain.split_domains(quotient_degree)
        //     })
        //     .collect::<Vec<_>>();

        // for (chip, trace_domain, qc_domains, values) in izip!(
        //     chips.iter(),
        //     trace_domains,
        //     quotient_chunk_domains,
        //     opened_values.chips.iter(),
        // ) {
        //     Self::verify_constraints(
        //         chip,
        //         values.clone(),
        //         trace_domain,
        //         qc_domains,
        //         zeta,
        //         alpha,
        //         &permutation_challenges,
        //     )
        //     .map_err(|_| VerificationError::OodEvaluationMismatch(chip.name()))?;
        // }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sp1_core::{
        stark::{RiscvAir, ShardCommitment, ShardProof, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };
    use sp1_recursion_compiler::{
        ir::{Builder, Config, Usize},
        verifier::fri::types::{Commitment, DIGEST_SIZE},
    };

    use crate::{
        fri::{const_fri_proof, const_two_adic_pcs_proof},
        types::{ChipOpening, ShardOpenedValuesVariable, ShardProofVariable},
    };

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RiscvAir<F>;

    pub(crate) fn const_proof<C, A>(
        builder: &mut Builder<C>,
        proof: ShardProof<SC>,
    ) -> ShardProofVariable<C>
    where
        C: Config<F = F, EF = EF>,
    {
        let index = builder.materialize(Usize::Const(proof.index));

        // Set up the commitments.
        let mut main_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
        let mut permutation_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
        let mut quotient_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);

        let main_commit_val: [_; DIGEST_SIZE] = proof.commitment.main_commit.into();
        let perm_commit_val: [_; DIGEST_SIZE] = proof.commitment.permutation_commit.into();
        let quotient_commit_val: [_; DIGEST_SIZE] = proof.commitment.quotient_commit.into();
        for (i, ((main_val, perm_val), quotient_val)) in main_commit_val
            .into_iter()
            .zip(perm_commit_val)
            .zip(quotient_commit_val)
            .enumerate()
        {
            builder.set(&mut main_commit, i, main_val);
            builder.set(&mut permutation_commit, i, perm_val);
            builder.set(&mut quotient_commit, i, quotient_val);
        }

        let commitment = ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        };

        // Set up the opened values.
        let opened_values = ShardOpenedValuesVariable {
            chips: proof
                .opened_values
                .chips
                .iter()
                .map(|values| ChipOpening::from_constant(builder, values))
                .collect(),
        };

        let opening_proof = const_two_adic_pcs_proof(builder, proof.opening_proof);

        ShardProofVariable {
            index: Usize::Var(index),
            commitment,
            opened_values,
            opening_proof,
        }
    }

    #[test]
    fn test_proof_challenges() {}

    #[test]
    fn test_verify_shard() {}
}
