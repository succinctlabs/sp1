use itertools::{izip, Itertools};
use p3_commit::PolynomialSpace;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::stark::config::OuterChallengeMmcs;

use crate::mmcs::verify_batch;
use crate::types::FriChallenges;
use crate::types::FriProofVariable;
use crate::types::FriQueryProofVariable;
use crate::types::OuterDigestVariable;
use crate::types::TwoAdicPcsProofVariable;
use crate::types::TwoAdicPcsRoundVariable;
use crate::{challenger::MultiField32ChallengerVariable, DIGEST_SIZE};

pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiField32ChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];

    for i in 0..proof.commit_phase_commits.len() {
        let commitment: [Var<C::N>; DIGEST_SIZE] = proof.commit_phase_commits[i];
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample_ext(builder);
        betas.push(sample);
    }

    // Observe the final polynomial.
    let final_poly_felts = builder.ext2felt_circuit(proof.final_poly);
    final_poly_felts.iter().for_each(|felt| {
        challenger.observe(builder, *felt);
    });

    assert_eq!(proof.query_proofs.len(), config.num_queries);
    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Var<_>> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(builder, log_max_height))
        .collect();

    FriChallenges {
        query_indices,
        betas,
    }
}

pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut MultiField32ChallengerVariable<C>,
    rounds: Vec<TwoAdicPcsRoundVariable<C>>,
) {
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let log_global_max_height = proof.fri_proof.commit_phase_commits.len() + config.log_blowup;

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<C::F, C::EF>> =
        vec![builder.eval(SymbolicExt::from_f(C::EF::one()))];

    let reduced_openings = proof
        .query_openings
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, &index)| {
            let mut ro: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::from_f(C::EF::zero())); 32];
            // An array of the current power for each log_height.
            let mut log_height_pow = [0usize; 32];

            for (batch_opening, round) in izip!(query_opening.clone(), &rounds) {
                let batch_commit = round.batch_commit;
                let mats = &round.mats;
                let batch_heights = mats
                    .iter()
                    .map(|mat| mat.domain.size() << config.log_blowup)
                    .collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let index_bits = builder.num2bits_v_circuit(index, 32);
                let reduced_index_bits = index_bits[bits_reduced..].to_vec();

                verify_batch::<C, 1>(
                    builder,
                    batch_commit,
                    batch_dims,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );
                for (mat_opening, mat) in izip!(batch_opening.opened_values.clone(), mats) {
                    let mat_domain = mat.domain;
                    let mat_points = &mat.points;
                    let mat_values = &mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let rev_reduced_index = builder
                        .reverse_bits_len_circuit(index_bits[bits_reduced..].to_vec(), log_height);

                    let g = builder.generator();
                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        builder.exp_f_bits(two_adic_generator, rev_reduced_index);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        let mut acc: Ext<C::F, C::EF> =
                            builder.eval(SymbolicExt::from_f(C::EF::zero()));
                        for (p_at_x, &p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let pow = log_height_pow[log_height];
                            // Fill in any missing powers of alpha.
                            (alpha_pows.len()..pow + 1).for_each(|_| {
                                let new_alpha = builder.eval(*alpha_pows.last().unwrap() * alpha);
                                builder.reduce_e(new_alpha);
                                alpha_pows.push(new_alpha);
                            });
                            acc = builder.eval(acc + (alpha_pows[pow] * (p_at_z - p_at_x[0])));
                            log_height_pow[log_height] += 1;
                        }
                        ro[log_height] = builder.eval(ro[log_height] + acc / (*z - x));
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();

    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        reduced_openings,
    );
}

pub fn verify_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for (&index, query_proof, ro) in izip!(
        &challenges.query_indices,
        &proof.query_proofs,
        reduced_openings
    ) {
        let folded_eval = verify_query(
            builder,
            proof.commit_phase_commits.clone(),
            index,
            query_proof.clone(),
            challenges.betas.clone(),
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<OuterDigestVariable<C>>,
    index: Var<C::N>,
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<C::F, C::EF> = builder.eval(SymbolicExt::from_f(C::EF::zero()));
    let two_adic_generator = builder.eval(SymbolicExt::from_f(C::EF::two_adic_generator(
        log_max_height,
    )));
    let index_bits = builder.num2bits_v_circuit(index, 32);
    let rev_reduced_index = builder.reverse_bits_len_circuit(index_bits.clone(), log_max_height);
    let mut x = builder.exp_e_bits(two_adic_generator, rev_reduced_index);
    builder.reduce_e(x);

    let mut offset = 0;
    for (log_folded_height, commit, step, beta) in izip!(
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    ) {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let one: Var<_> = builder.eval(C::N::one());
        let index_sibling: Var<_> = builder.eval(one - index_bits.clone()[offset]);
        let index_pair = &index_bits[(offset + 1)..];

        let evals_ext = [
            builder.select_ef(index_sibling, folded_eval, step.sibling_value),
            builder.select_ef(index_sibling, step.sibling_value, folded_eval),
        ];
        let evals_felt = vec![
            builder.ext2felt_circuit(evals_ext[0]).to_vec(),
            builder.ext2felt_circuit(evals_ext[1]).to_vec(),
        ];

        let dims = &[Dimensions {
            width: 2,
            height: (1 << log_folded_height),
        }];
        verify_batch::<C, 4>(
            builder,
            commit,
            dims.to_vec(),
            index_pair.to_vec(),
            [evals_felt].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new = builder.eval(x * C::EF::two_adic_generator(1));
        let xs = [
            builder.select_ef(index_sibling, x, xs_new),
            builder.select_ef(index_sibling, xs_new, x),
        ];
        folded_eval = builder
            .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
        x = builder.eval(x * x);
        builder.reduce_e(x);
        offset += 1;
    }

    folded_eval
}

#[cfg(test)]
pub mod tests {

    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::AbstractField;
    use p3_fri::{verifier, TwoAdicFriPcsProof};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Ext, Felt, SymbolicExt, Var, Witness},
    };
    use sp1_recursion_core::stark::config::{
        outer_perm, test_fri_config, OuterChallenge, OuterChallengeMmcs, OuterChallenger,
        OuterCompress, OuterDft, OuterFriProof, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;

    use super::{verify_shape_and_sample_challenges, verify_two_adic_pcs, TwoAdicPcsRoundVariable};
    use crate::{
        challenger::MultiField32ChallengerVariable,
        fri::FriQueryProofVariable,
        types::{
            BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
            OuterDigestVariable, TwoAdicPcsMatsVariable, TwoAdicPcsProofVariable,
        },
        DIGEST_SIZE,
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
                [commit; DIGEST_SIZE]
            })
            .collect::<Vec<_>>();

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
                            builder.eval(SymbolicExt::from_f(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                [commit; DIGEST_SIZE]
                            })
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable {
                            sibling_value,
                            opening_proof,
                        }
                    })
                    .collect::<Vec<_>>();
                FriQueryProofVariable {
                    commit_phase_openings,
                }
            })
            .collect::<Vec<_>>();

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly: builder.eval(SymbolicExt::from_f(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    pub fn const_two_adic_pcs_proof(
        builder: &mut Builder<OuterConfig>,
        proof: TwoAdicFriPcsProof<OuterVal, OuterChallenge, OuterValMmcs, OuterChallengeMmcs>,
    ) -> TwoAdicPcsProofVariable<OuterConfig> {
        let fri_proof = const_fri_proof(builder, proof.fri_proof);
        let query_openings = proof
            .query_openings
            .iter()
            .map(|query_opening| {
                query_opening
                    .iter()
                    .map(|opening| BatchOpeningVariable {
                        opened_values: opening
                            .opened_values
                            .iter()
                            .map(|opened_value| {
                                opened_value
                                    .iter()
                                    .map(|value| vec![builder.eval::<Felt<OuterVal>, _>(*value)])
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>(),
                        opening_proof: opening
                            .opening_proof
                            .iter()
                            .map(|opening_proof| [builder.eval(opening_proof[0])])
                            .collect::<Vec<_>>(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        TwoAdicPcsProofVariable {
            fri_proof,
            query_openings,
        }
    }

    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<OuterConfig>,
        commit: [Bn254Fr; DIGEST_SIZE],
        os: Vec<(
            TwoAdicMultiplicativeCoset<OuterVal>,
            Vec<(OuterChallenge, Vec<OuterChallenge>)>,
        )>,
    ) -> (
        OuterDigestVariable<OuterConfig>,
        Vec<TwoAdicPcsRoundVariable<OuterConfig>>,
    ) {
        let commit: OuterDigestVariable<OuterConfig> = [builder.eval(commit[0])];

        let mut mats = Vec::new();
        for (domain, poly) in os.into_iter() {
            let points: Vec<Ext<OuterVal, OuterChallenge>> = poly
                .iter()
                .map(|(p, _)| builder.eval(SymbolicExt::from_f(*p)))
                .collect::<Vec<_>>();
            let values: Vec<Vec<Ext<OuterVal, OuterChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::from_f(*t)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mat = TwoAdicPcsMatsVariable {
                domain,
                points,
                values,
            };
            mats.push(mat);
        }

        (
            commit,
            vec![TwoAdicPcsRoundVariable {
                batch_commit: commit,
                mats,
            }],
        )
    }

    #[test]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let fri_config = test_fri_config();
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
            &test_fri_config(),
            &proof.fri_proof,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let config = test_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = MultiField32ChallengerVariable::new(&mut builder);
        let commit: [Bn254Fr; DIGEST_SIZE] = commit.into();
        let commit: Var<_> = builder.eval(commit[0]);
        challenger.observe_commitment(&mut builder, [commit]);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges =
            verify_shape_and_sample_challenges(&mut builder, &config, &fri_proof, &mut challenger);

        for i in 0..fri_challenges_gt.betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::from_f(fri_challenges_gt.betas[i]),
                fri_challenges.betas[i],
            );
        }

        for i in 0..fri_challenges_gt.query_indices.len() {
            builder.assert_var_eq(
                Bn254Fr::from_canonical_usize(fri_challenges_gt.query_indices[i]),
                fri_challenges.query_indices[i],
            );
        }

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }

    #[test]
    fn test_verify_two_adic_pcs() {
        let mut rng = &mut OsRng;
        let log_degrees = &[19, 19];
        let perm = outer_perm();
        let fri_config = test_fri_config();
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
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 100),
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
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        challenger.sample_ext_element::<OuterChallenge>();
        let os: Vec<(
            TwoAdicMultiplicativeCoset<OuterVal>,
            Vec<(OuterChallenge, Vec<OuterChallenge>)>,
        )> = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let config = test_fri_config();
        let proof = const_two_adic_pcs_proof(&mut builder, proof);
        let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = MultiField32ChallengerVariable::new(&mut builder);
        challenger.observe_commitment(&mut builder, commit);
        challenger.sample_ext(&mut builder);
        verify_two_adic_pcs(&mut builder, &config, &proof, &mut challenger, rounds);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }
}
