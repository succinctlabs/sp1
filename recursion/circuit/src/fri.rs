use std::cmp::Reverse;

use itertools::Itertools;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
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

// pub fn verify_challenges<C: Config>(
//     builder: &mut Builder<C>,
//     config: &FriConfig<OuterChallengeMmcs>,
//     proof: &FriProofVariable<C>,
//     challenges: &FriChallenges<C>,
//     reduced_openings: &Array<C, Array<C, Ext<C::F, C::EF>>>,
// ) where
//     C::EF: TwoAdicField,
// {
//     let log_max_height = proof.commit_phase_commits.vec().len() + config.log_blowup;
//     for i in 0..challenges.query_indices.vec().len() {
//         let index = challenges.query_indices.vec()[i];
//         let query_proof = &proof.query_proofs.vec()[i];
//         let ro = &reduced_openings.vec()[i];

//         let folded_eval = verify_query(
//             builder,
//             config,
//             &proof.commit_phase_commits,
//             index,
//             query_proof,
//             &challenges.betas,
//             ro,
//             log_max_height,
//         );

//         // builder.assert_ext_eq(folded_eval, proof.final_poly);
//     }
// }

// pub fn verify_query<C: Config>(
//     builder: &mut Builder<C>,
//     config: &FriConfig<OuterChallengeMmcs>,
//     commit_phase_commits: &Array<C, Array<C, Var<C::N>>>,
//     index: Var<C::N>,
//     proof: &FriQueryProofVariable<C>,
//     betas: &Array<C, Ext<C::F, C::EF>>,
//     reduced_openings: &Array<C, Ext<C::F, C::EF>>,
//     log_max_height: usize,
// ) -> Ext<C::F, C::EF>
// where
//     C::EF: TwoAdicField,
// {
//     let folded_eval: Ext<C::F, C::EF> = builder.eval(C::F::zero());
//     let two_adic_generator_ef = builder.eval(SymbolicExt::Const(C::EF::two_adic_generator(
//         log_max_height,
//     )));
//     let power = builder.reverse_bits_len(index, log_max_height);
//     let x = builder.exp_usize_ef(two_adic_generator_ef, power);
//     let index_bits = builder.num2bits_v_circuit(index, 32);

//     // builder
//     //     .range(0, commit_phase_commits.len())
//     //     .for_each(|i, builder| {
//     //         let log_folded_height: Var<_> = builder.eval(log_max_height - i - C::N::one());
//     //         let log_folded_height_plus_one: Var<_> = builder.eval(log_folded_height + C::N::one());
//     //         let commit = builder.get(commit_phase_commits, i);
//     //         let step = builder.get(&proof.commit_phase_openings, i);
//     //         let beta = builder.get(betas, i);

//     //         let reduced_opening = builder.get(reduced_openings, log_folded_height_plus_one);
//     //         builder.assign(folded_eval, folded_eval + reduced_opening);

//     //         let index_bit = builder.get(&index_bits, i);
//     //         let index_sibling_mod_2: Var<C::N> =
//     //             builder.eval(SymbolicVar::Const(C::N::one()) - index_bit);
//     //         let i_plus_one = builder.eval(i + C::N::one());
//     //         let index_pair = index_bits.shift(builder, i_plus_one);

//     //         let mut evals: Array<C, Ext<C::F, C::EF>> = builder.array(2);
//     //         builder.set(&mut evals, 0, folded_eval);
//     //         builder.set(&mut evals, 1, folded_eval);
//     //         builder.set(&mut evals, index_sibling_mod_2, step.sibling_value);

//     //         let two: Var<C::N> = builder.eval(C::N::from_canonical_u32(2));
//     //         let dims = Dimensions::<C> {
//     //             height: builder.exp_usize_v(two, Usize::Var(log_folded_height)),
//     //         };
//     //         let mut dims_slice: Array<C, Dimensions<C>> = builder.array(1);
//     //         builder.set(&mut dims_slice, 0, dims);

//     //         let mut opened_values = builder.array(1);
//     //         builder.set(&mut opened_values, 0, evals.clone());
//     //         verify_batch::<C, 4>(
//     //             builder,
//     //             &commit,
//     //             dims_slice,
//     //             index_pair,
//     //             opened_values,
//     //             &step.opening_proof,
//     //         );

//     //         let mut xs: Array<C, Ext<C::F, C::EF>> = builder.array(2);
//     //         let two_adic_generator_one = builder.two_adic_generator(Usize::Const(1));
//     //         builder.set(&mut xs, 0, x);
//     //         builder.set(&mut xs, 1, x);
//     //         builder.set(&mut xs, index_sibling_mod_2, x * two_adic_generator_one);

//     //         let xs_0 = builder.get(&xs, 0);
//     //         let xs_1 = builder.get(&xs, 1);
//     //         let eval_0 = builder.get(&evals, 0);
//     //         let eval_1 = builder.get(&evals, 1);
//     //         builder.assign(
//     //             folded_eval,
//     //             eval_0 + (beta - xs_0) * (eval_1 - eval_0) / (xs_1 - xs_0),
//     //         );

//     //         builder.assign(x, x * x);
//     //     });

//     // folded_eval
//     todo!()
// }

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
