use p3_fri::FriConfig;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_compiler::prelude::Array;
use sp1_recursion_compiler::prelude::MemVariable;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::stark::config::OuterChallengeMmcs;
use sp1_recursion_derive::DslVariable;

use crate::{challenger::MultiFieldChallengerVariable, DIGEST_SIZE};

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];

    #[allow(clippy::never_loop)]
    for i in 0..proof.commit_phase_commits.vec().len() {
        let commitment: [Var<C::N>; DIGEST_SIZE] = proof.commit_phase_commits.vec()[i]
            .vec()
            .try_into()
            .unwrap();
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample_ext(builder);
        betas.push(sample);
    }

    assert_eq!(proof.query_proofs.vec().len(), config.num_queries);

    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.vec().len() + config.log_blowup;
    let query_indices: Vec<Var<_>> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(builder, log_max_height))
        .collect();

    FriChallenges {
        query_indices: builder.vec(query_indices),
        betas: builder.vec(betas),
    }
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(DslVariable, Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Array<C, Array<C, Var<C::N>>>,
    pub query_proofs: Array<C, FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Array<C, Array<C, Var<C::N>>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(DslVariable, Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Array<C, Var<C::N>>,
    pub betas: Array<C, Ext<C::F, C::EF>>,
}

#[cfg(test)]
mod tests {

    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::Pcs;
    use p3_field::AbstractField;
    use p3_fri::verifier;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use serial_test::serial;
    use sp1_recursion_compiler::{
        constraints::{gnark_ffi, ConstraintBackend},
        ir::{Builder, SymbolicExt, Var},
        OuterConfig,
    };
    use sp1_recursion_core::stark::config::{
        outer_fri_config, outer_perm, OuterChallenge, OuterChallenger, OuterCompress, OuterDft,
        OuterFriProof, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };

    use super::{
        verify_shape_and_sample_challenges, FriCommitPhaseProofStepVariable, FriProofVariable,
    };
    use crate::{
        challenger::MultiFieldChallengerVariable, fri::FriQueryProofVariable, DIGEST_SIZE,
    };

    pub fn const_fri_proof(
        builder: &mut Builder<OuterConfig>,
        fri_proof: OuterFriProof,
    ) -> FriProofVariable<OuterConfig> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [Bn254Fr; DIGEST_SIZE] = (*commit).into();
                let commit: Var<_> = builder.eval(commit[0]);
                builder.vec(vec![commit])
            })
            .collect::<Vec<_>>();
        let commit_phase_commits = builder.vec(commit_phase_commits);

        // Set the query proofs.
        let query_proofs = fri_proof
            .query_proofs
            .iter()
            .map(|query_proof| {
                let commit_phase_openings = query_proof
                    .commit_phase_openings
                    .iter()
                    .map(|commit_phase_opening| {
                        let sibling_value =
                            builder.eval(SymbolicExt::Const(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                builder.vec(vec![commit])
                            })
                            .collect::<Vec<_>>();
                        let opening_proof = builder.vec(opening_proof);
                        FriCommitPhaseProofStepVariable {
                            sibling_value,
                            opening_proof,
                        }
                    })
                    .collect::<Vec<_>>();
                let commit_phase_openings = builder.vec(commit_phase_openings);
                FriQueryProofVariable {
                    commit_phase_openings,
                }
            })
            .collect::<Vec<_>>();
        let query_proofs = builder.vec(query_proofs);

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly: builder.eval(SymbolicExt::Const(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    #[test]
    #[serial]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let fri_config = outer_fri_config();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs = OuterPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<OuterChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (_, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let _: OuterChallenge = challenger.sample();
        let fri_challenges_gt = verifier::verify_shape_and_sample_challenges(
            &outer_fri_config(),
            &proof.fri_proof,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let config = outer_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = MultiFieldChallengerVariable::new(&mut builder);
        let commit: [Bn254Fr; DIGEST_SIZE] = commit.into();
        let commit: Var<_> = builder.eval(commit[0]);
        challenger.observe_commitment(&mut builder, [commit]);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges =
            verify_shape_and_sample_challenges(&mut builder, &config, &fri_proof, &mut challenger);

        for i in 0..fri_challenges_gt.betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::Const(fri_challenges_gt.betas[i]),
                fri_challenges.betas.vec()[i],
            );
        }

        for i in 0..fri_challenges_gt.query_indices.len() {
            builder.assert_var_eq(
                Bn254Fr::from_canonical_usize(fri_challenges_gt.query_indices[i]),
                fri_challenges.query_indices.vec()[i],
            );
        }

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }
}
