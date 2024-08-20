use std::iter::zip;

use itertools::{izip, Itertools};
use p3_commit::PolynomialSpace;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::stark::config::OuterChallenge;
use sp1_recursion_core::stark::config::OuterChallengeMmcs;

use crate::mmcs::verify_batch;
use crate::types::FriChallenges;
use crate::types::FriCommitPhaseProofStepVariable;
use crate::types::FriProofVariable;
use crate::types::FriQueryProofVariable;
use crate::types::NormalizeQueryProofVariable;
use crate::types::OuterDigestVariable;
use crate::types::TwoAdicPcsProofVariable;
use crate::types::TwoAdicPcsRoundVariable;
use crate::utils::access_index_with_var_e;
use crate::{challenger::MultiField32ChallengerVariable, DIGEST_SIZE};

pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    log_max_height: usize,
    challenger: &mut MultiField32ChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];
    let mut normalize_betas = vec![];

    for i in 0..proof.normalize_phase_commits.len() {
        let commitment: [Var<C::N>; DIGEST_SIZE] = proof.normalize_phase_commits[i];
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample_ext(builder);
        normalize_betas.push(sample);
    }

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

    let query_indices: Vec<Var<_>> =
        (0..config.num_queries).map(|_| challenger.sample_bits(builder, log_max_height)).collect();

    FriChallenges { query_indices, betas, normalize_betas }
}

pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut MultiField32ChallengerVariable<C>,
    rounds: Vec<TwoAdicPcsRoundVariable<C>>,
) {
    builder.cycle_tracker("2adic");
    let alpha = challenger.sample_ext(builder);
    let log_global_max_height = log2_strict_usize(
        rounds
            .iter()
            .map(|round| {
                round.mats.iter().map(|mat| mat.domain.size() << config.log_blowup).max().unwrap()
            })
            .max()
            .unwrap(),
    );

    let fri_challenges = verify_shape_and_sample_challenges(
        builder,
        config,
        &proof.fri_proof,
        log_global_max_height,
        challenger,
    );

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<C::F, C::EF>> =
        vec![builder.eval(SymbolicExt::from_f(C::EF::one()))];

    let reduced_openings = proof
        .query_openings
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, &index)| {
            let mut ro: [Option<Ext<C::F, C::EF>>; 32] = [None; 32];
            // An array of the current power for each log_height.
            let mut log_height_pow = [0usize; 32];

            for (batch_opening, round) in izip!(query_opening.clone(), &rounds) {
                let batch_commit = round.batch_commit;
                let mats = &round.mats;
                let batch_heights =
                    mats.iter().map(|mat| mat.domain.size() << config.log_blowup).collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let index_bits = builder.num2bits_v_circuit(index, log_global_max_height);
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
                        builder.cycle_tracker("2adic-hotloop");
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
                        if let Some(r) = &mut ro[log_height] {
                            *r = builder.eval(*r + acc / (*z - x));
                        } else {
                            ro[log_height] = Some(builder.eval(acc / (*z - x)));
                        }
                        builder.cycle_tracker("2adic-hotloop");
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();
    builder.cycle_tracker("2adic");

    builder.cycle_tracker("challenges");
    verify_challenges(builder, config, &proof.fri_proof, &fri_challenges, reduced_openings);
    builder.cycle_tracker("challenges");
}

pub fn verify_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Option<Ext<C::F, C::EF>>; 32]>,
) {
    let log_max_normalized_height =
        config.log_arity * proof.commit_phase_commits.len() + config.log_blowup;

    let log_max_height =
        reduced_openings[0].iter().enumerate().filter_map(|(i, v)| v.map(|_| i)).max().unwrap();

    for (&index, query_proof, normalize_query_proof, ro) in izip!(
        &challenges.query_indices,
        proof.query_proofs.clone(),
        proof.normalize_query_proofs.clone(),
        reduced_openings
    ) {
        let index_bits = builder.num2bits_v_circuit(index, 32);
        let normalized_openings = verify_normalization_phase(
            builder,
            config,
            proof.normalize_phase_commits.clone(),
            index_bits.clone(),
            normalize_query_proof,
            &challenges.normalize_betas,
            &ro,
            log_max_height,
        );

        let new_index_bits = index_bits[log_max_height - log_max_normalized_height..].to_vec();
        let new_index = builder.bits2num_v_circuit(&new_index_bits);

        let folded_eval = verify_query(
            builder,
            config,
            proof.commit_phase_commits.clone(),
            new_index,
            query_proof.clone(),
            challenges.betas.clone(),
            normalized_openings,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

fn verify_normalization_phase<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    normalize_phase_commits: Vec<OuterDigestVariable<C>>,
    index_bits: Vec<Var<C::N>>,
    normalize_proof: NormalizeQueryProofVariable<C>,
    betas: &[Ext<C::F, C::EF>],
    reduced_openings: &[Option<Ext<C::F, C::EF>>; 32],
    log_max_height: usize,
) -> [Ext<C::F, C::EF>; 32] {
    // Compute the heights at which we have vectors that need to be normalized.
    let heights = reduced_openings
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|_| i))
        .filter(|i| (i >= &config.log_blowup) && (i - config.log_blowup) % config.log_arity != 0)
        .rev();

    // Populate the return value with zeros, or with the reduced openings at the correct indices.
    let mut new_openings: [Ext<_, _>; 32] = core::array::from_fn(|i| {
        if i >= config.log_blowup && (i - config.log_blowup) % config.log_arity == 0 {
            reduced_openings[i].unwrap_or(builder.eval(SymbolicExt::from_f(C::EF::zero())))
        } else {
            builder.eval(SymbolicExt::from_f(C::EF::zero()))
        }
    });

    let generator = builder.eval(SymbolicFelt::from_f(C::F::two_adic_generator(log_max_height)));

    let rev_reduced_index = builder.reverse_bits_len_circuit(index_bits.clone(), log_max_height);
    let x = builder.exp_f_bits(generator, rev_reduced_index);

    for (commit, log_height, step, beta) in izip!(
        normalize_phase_commits.into_iter(),
        heights,
        normalize_proof.normalize_phase_openings,
        betas
    ) {
        // We shouldn't have normalize phase commitments where the height is equal to a multiple of
        //the arity added to the log_blowup.
        debug_assert!((log_height - config.log_blowup) % config.log_arity != 0);

        let new_x: Felt<_> = builder.exp_power_of_2(x, log_max_height - log_height);
        let num_folds = (log_height - config.log_blowup) % config.log_arity;
        let log_folded_height = log_height - num_folds;

        let g = C::F::two_adic_generator(num_folds);
        let g_powers = g.powers().take(1 << num_folds).collect::<Vec<_>>();

        let xs = g_powers.iter().map(|y| builder.eval(new_x * *y)).collect::<Vec<Felt<_>>>();

        debug_assert!((log_folded_height - config.log_blowup) % config.log_arity == 0);

        let new_index_bits = index_bits[(log_max_height - log_height)..].to_vec();

        let new_index = builder.bits2num_v_circuit(&new_index_bits);

        // Verify the fold step and update the new openings. `folded_height` is the closest
        // "normalized" height to `log_height`. `step` and `commit` give us the information necessary
        // to fold the unnormalized opening from `log_height` multiple steps down to `folded_height`.
        let fold_add = verify_fold_step(
            builder,
            reduced_openings[log_height].unwrap(),
            *beta,
            num_folds,
            step,
            commit,
            new_index,
            log_height - num_folds,
            xs,
        );
        new_openings[log_folded_height] = builder.eval(new_openings[log_folded_height] + fold_add);
    }

    new_openings
}

fn verify_fold_step<C: Config>(
    builder: &mut Builder<C>,
    folded_eval: Ext<C::F, C::EF>,
    beta: Ext<C::F, C::EF>,
    num_folds: usize,
    step: FriCommitPhaseProofStepVariable<C>,
    commit: OuterDigestVariable<C>,
    index: Var<C::N>,
    log_folded_height: usize,
    xs: Vec<Felt<C::F>>,
) -> Ext<C::F, C::EF> {
    let index_bits = builder.num2bits_v_circuit(index, 32);
    let index_self_in_siblings = index_bits[..num_folds].to_vec();
    let index_set = index_bits[num_folds..].to_vec();

    let evals: Vec<Ext<C::F, C::EF>> = step.siblings.clone();
    let expected_eval = access_index_with_var_e(builder, &evals, index_self_in_siblings.clone());
    builder.assert_ext_eq(expected_eval, folded_eval);

    let evals_felt: Vec<Vec<Felt<<C as Config>::F>>> =
        evals.iter().map(|eval| builder.ext2felt_circuit(*eval).to_vec()).collect();

    let dims = &[Dimensions { width: (1 << num_folds), height: (1 << log_folded_height) }];
    verify_batch::<C, 4>(
        builder,
        commit,
        dims.to_vec(),
        index_set.to_vec(),
        [evals_felt].to_vec(),
        step.opening_proof.clone(),
    );

    // let g = C::F::two_adic_generator(num_folds);
    // let g_powers = g.powers().take(1 << num_folds).collect::<Vec<_>>();

    // let xs = g_powers
    //     .iter()
    //     .map(|y| builder.eval(x * *y))
    //     .collect::<Vec<Felt<_>>>();

    let mut ord_idx_bits = index_self_in_siblings;
    let mut ord_evals: Vec<Ext<_, _>> = vec![];

    for _ in 0..(1 << num_folds) {
        let new_eval = access_index_with_var_e(builder, &evals, ord_idx_bits.clone());
        ord_evals.push(new_eval);
        ord_idx_bits = next_index_in_coset(builder, ord_idx_bits);
    }

    interpolate_fft_and_evaluate(builder, &xs, &ord_evals, beta)
}

pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    commit_phase_commits: Vec<OuterDigestVariable<C>>,
    mut index: Var<C::N>,
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    // log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let log_max_normalized_height =
        config.log_arity * commit_phase_commits.len() + config.log_blowup;

    for (_, ro) in reduced_openings.iter().enumerate().filter(|(i, _)| {
        (i >= &config.log_blowup) && (i - config.log_blowup) % config.log_arity != 0
    }) {
        builder.assert_ext_eq(*ro, SymbolicExt::from_f(C::EF::zero()));
    }
    let g = C::F::two_adic_generator(config.log_arity);
    let g_powers = g.powers().take(1 << config.log_arity).collect::<Vec<_>>();

    let mut folded_eval: Ext<C::F, C::EF> = reduced_openings[log_max_normalized_height];
    let two_adic_generator =
        builder.eval(SymbolicFelt::from_f(C::F::two_adic_generator(log_max_normalized_height)));
    let index_bits = builder.num2bits_v_circuit(index, 32);
    let rev_reduced_index =
        builder.reverse_bits_len_circuit(index_bits.clone(), log_max_normalized_height);
    let mut x = builder.exp_f_bits(two_adic_generator, rev_reduced_index);
    // builder.reduce_f(x);

    for (i, (log_folded_height, commit, step, beta)) in izip!(
        (config.log_blowup..log_max_normalized_height + 1 - config.log_arity)
            .rev()
            .step_by(config.log_arity),
        commit_phase_commits.into_iter(),
        proof.commit_phase_openings,
        betas,
    )
    .enumerate()
    {
        let xs = g_powers.iter().map(|y| builder.eval(x * *y)).collect();
        folded_eval = verify_fold_step(
            builder,
            folded_eval,
            beta,
            config.log_arity,
            step,
            commit,
            index,
            log_folded_height,
            xs,
        );
        index = builder.bits2num_v_circuit(&index_bits[(i + 1) * config.log_arity..]);
        x = builder.exp_power_of_2(x, config.log_arity);

        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height]);
    }

    folded_eval
}

fn next_index_in_coset<C: Config>(
    builder: &mut Builder<C>,
    index: Vec<Var<C::N>>,
) -> Vec<Var<C::N>> {
    // TODO better names.
    let len = index.len();
    let result = builder.reverse_bits_len_circuit(index, len);
    let mut result = builder.bits2num_v_circuit(&result);
    result = builder.eval(result + C::N::one());
    let result_bits = builder.num2bits_v_circuit(result, len + 1)[..len + 1].to_vec();

    builder.reverse_bits_len_circuit(result_bits, len)
}

// Inefficient algorithm for interpolation and evaluation of a polynomial at a point.
fn interpolate_fft_and_evaluate<C: Config>(
    builder: &mut Builder<C>,
    coset: &[Felt<C::F>],
    ys: &[Ext<C::F, C::EF>],
    beta: Ext<C::F, C::EF>,
) -> Ext<C::F, C::EF> {
    assert_eq!(coset.len(), ys.len());
    if ys.len() == 1 {
        return ys[0];
    }
    let beta_sq = builder.eval(beta * beta);
    let next_coset =
        coset.iter().take(coset.len() / 2).copied().map(|x| builder.eval(x * x)).collect_vec();
    let even_ys = izip!(ys.iter().take(ys.len() / 2), ys.iter().skip(ys.len() / 2))
        .map(|(&a, &b)| builder.eval((a + b) / C::F::two()))
        .collect_vec();
    let odd_ys = izip!(
        ys.iter().take(ys.len() / 2),
        ys.iter().skip(ys.len() / 2),
        coset.iter().take(ys.len() / 2)
    )
    .map(|(&a, &b, &x)| builder.eval((a - b) / (x * C::F::two())))
    .collect_vec();
    let even_result = interpolate_fft_and_evaluate(builder, &next_coset, &even_ys, beta_sq);
    let odd_result = interpolate_fft_and_evaluate(builder, &next_coset, &odd_ys, beta_sq);
    builder.reduce_e(odd_result);
    builder.reduce_e(even_result);
    builder.eval(even_result + beta * odd_result)
}

#[cfg(test)]
pub mod tests {

    use std::{env, os};

    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::{
        extension::BinomialExtensionField, AbstractExtensionField, AbstractField, ExtensionField,
    };
    use p3_fri::{
        verifier::{self},
        TwoAdicFriPcsProof,
    };
    use p3_matrix::dense::RowMajorMatrix;
    use p3_util::reverse_slice_index_bits;
    use rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    };
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt, SymbolicVar, Var, Witness},
    };
    use sp1_recursion_core::stark::config::{
        outer_perm, test_fri_config, OuterChallenge, OuterChallengeMmcs, OuterChallenger,
        OuterCompress, OuterDft, OuterFriProof, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;

    use super::{
        interpolate_fft_and_evaluate, next_index_in_coset, verify_shape_and_sample_challenges,
        verify_two_adic_pcs, TwoAdicPcsRoundVariable,
    };
    use crate::{
        challenger::MultiField32ChallengerVariable,
        fri::FriQueryProofVariable,
        types::{
            BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
            NormalizeQueryProofVariable, OuterDigestVariable, TwoAdicPcsMatsVariable,
            TwoAdicPcsProofVariable,
        },
        DIGEST_SIZE,
    };

    pub const TEST_LOG_ARITY: usize = 4;

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

        let normalize_phase_commits = fri_proof
            .normalize_phase_commits
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
                        let siblings = commit_phase_opening
                            .siblings
                            .iter()
                            .map(|sibling| builder.eval(SymbolicExt::from_f(*sibling)))
                            .collect();
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                [commit; DIGEST_SIZE]
                            })
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable { siblings, opening_proof }
                    })
                    .collect::<Vec<_>>();
                FriQueryProofVariable { commit_phase_openings }
            })
            .collect::<Vec<_>>();

        let normalize_query_proofs = fri_proof
            .normalize_query_proofs
            .iter()
            .map(|query_proof| {
                let normalize_phase_openings = query_proof
                    .normalize_phase_openings
                    .iter()
                    .map(|commit_phase_opening| {
                        let siblings = commit_phase_opening
                            .siblings
                            .iter()
                            .map(|sibling| builder.eval(SymbolicExt::from_f(*sibling)))
                            .collect();
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                [commit; DIGEST_SIZE]
                            })
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable { siblings, opening_proof }
                    })
                    .collect::<Vec<_>>();
                NormalizeQueryProofVariable { normalize_phase_openings }
            })
            .collect::<Vec<_>>();

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            normalize_phase_commits,
            normalize_query_proofs,
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
        TwoAdicPcsProofVariable { fri_proof, query_openings }
    }

    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<OuterConfig>,
        commit: [Bn254Fr; DIGEST_SIZE],
        os: Vec<(TwoAdicMultiplicativeCoset<OuterVal>, Vec<(OuterChallenge, Vec<OuterChallenge>)>)>,
    ) -> (OuterDigestVariable<OuterConfig>, Vec<TwoAdicPcsRoundVariable<OuterConfig>>) {
        let commit: OuterDigestVariable<OuterConfig> = [builder.eval(commit[0])];

        let mut mats = Vec::new();
        for (domain, poly) in os.into_iter() {
            let points: Vec<Ext<OuterVal, OuterChallenge>> =
                poly.iter().map(|(p, _)| builder.eval(SymbolicExt::from_f(*p))).collect::<Vec<_>>();
            let values: Vec<Vec<Ext<OuterVal, OuterChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::from_f(*t)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mat = TwoAdicPcsMatsVariable { domain, points, values };
            mats.push(mat);
        }

        (commit, vec![TwoAdicPcsRoundVariable { batch_commit: commit, mats }])
    }

    #[test]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut match env::var("REPRODUCIBLE") {
            Ok(_) => StdRng::seed_from_u64(42),
            Err(_) => StdRng::from_rng(OsRng).unwrap(),
        };
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let mut fri_config = test_fri_config();
        let log_blowup = fri_config.log_blowup;
        fri_config.log_arity = TEST_LOG_ARITY;
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs =
            OuterPcs::new(log_degrees.iter().copied().max().unwrap(), dft, val_mmcs, fri_config);

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
        let points = domains_and_polys.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
        let (_, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let _: OuterChallenge = challenger.sample();
        let fri_challenges_gt = verifier::verify_shape_and_sample_challenges(
            &test_fri_config(),
            &proof.fri_proof,
            log_degrees.iter().max().unwrap() + log_blowup,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let mut config = test_fri_config();
        config.log_arity = TEST_LOG_ARITY;
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = MultiField32ChallengerVariable::new(&mut builder);
        let commit: [Bn254Fr; DIGEST_SIZE] = commit.into();
        let commit: Var<_> = builder.eval(commit[0]);
        challenger.observe_commitment(&mut builder, [commit]);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges = verify_shape_and_sample_challenges(
            &mut builder,
            &config,
            &fri_proof,
            log_degrees.iter().max().unwrap() + log_blowup,
            &mut challenger,
        );

        for i in 0..fri_challenges_gt.betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::from_f(fri_challenges_gt.betas[i]),
                fri_challenges.betas[i],
            );
        }

        for i in 0..fri_challenges_gt.normalize_betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::from_f(fri_challenges_gt.normalize_betas[i]),
                fri_challenges.normalize_betas[i],
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
        let mut rng = match std::env::var("REPRODUCIBLE") {
            Ok(_) => StdRng::seed_from_u64(0xDEADBEEF),
            Err(_) => StdRng::from_rng(OsRng).unwrap(),
        };
        let log_degrees = &[19, 16];
        let perm = outer_perm();
        let mut fri_config = test_fri_config();
        fri_config.log_arity = TEST_LOG_ARITY;
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs =
            OuterPcs::new(log_degrees.iter().copied().max().unwrap(), dft, val_mmcs, fri_config);

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
        let points = domains_and_polys.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
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
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger).unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let mut config = test_fri_config();
        config.log_arity = TEST_LOG_ARITY;
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

    // #[test]
    // fn test_lagrange_interpolate() {
    //     // Define circuit.
    //     let mut builder = Builder::<OuterConfig>::default();

    //     let xs: Vec<Felt<_>> = [5, 1, 3, 9]
    //         .iter()
    //         .map(|x| builder.eval(SymbolicFelt::from_f(BabyBear::from_canonical_usize(*x))))
    //         .collect();

    //     let ys: Vec<Ext<_,_>> = [1, 2, 3, 4].iter().map(|y| {
    //         builder.eval(SymbolicExt::from_f(<sp1_recursion_compiler::config::OuterConfig as sp1_recursion_compiler::ir::Config>::EF::from_canonical_usize(
    //             *y,
    //         )))
    //     }).collect();

    //     for (x, y) in xs.iter().zip(ys.iter()) {
    //         let zero: Felt<_> = builder.eval(SymbolicFelt::from_f(BabyBear::zero()));
    //         let x_ext: Ext<_, _> = builder.felts2ext(&[*x, zero, zero, zero]);
    //         let expected_y = interpolate_lagrange_and_evaluate(&mut builder, &xs, &ys, x_ext);
    //         builder.assert_ext_eq(expected_y, *y);
    //     }

    //     let mut backend = ConstraintCompiler::<OuterConfig>::default();
    //     let constraints = backend.emit(builder.operations);
    //     PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    // }

    // #[test]
    // fn test_lagrange_interpolate_2() {
    //     // Define circuit.
    //     let mut builder = Builder::<OuterConfig>::default();

    //     let xs: Vec<Felt<_>> = [5, 1]
    //         .iter()
    //         .map(|x| builder.eval(SymbolicFelt::from_f(BabyBear::from_canonical_usize(*x))))
    //         .collect();

    //     let ys: Vec<Ext<_,_>> = [1, 2].iter().map(|y| {
    //         builder.eval(SymbolicExt::from_f(<sp1_recursion_compiler::config::OuterConfig as sp1_recursion_compiler::ir::Config>::EF::from_canonical_usize(
    //             *y,
    //         )))
    //     }).collect();

    //     for (x, y) in xs.iter().zip(ys.iter()) {
    //         let zero: Felt<_> = builder.eval(SymbolicFelt::from_f(BabyBear::zero()));
    //         let x_ext: Ext<_, _> = builder.felts2ext(&[*x, zero, zero, zero]);
    //         let expected_y = interpolate_lagrange_and_evaluate(&mut builder, &xs, &ys, x_ext);
    //         builder.assert_ext_eq(expected_y, *y);
    //     }

    //     let mut backend = ConstraintCompiler::<OuterConfig>::default();
    //     let constraints = backend.emit(builder.operations);
    //     PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    // }

    #[test]
    fn test_next_index_in_coset() {
        let expected_indices = (0..8).map(|index| p3_fri::verifier::next_index_in_coset(index, 3));
        let mut builder = Builder::<OuterConfig>::default();

        let indices = (0..8)
            .map(|x| builder.eval(SymbolicVar::from_f(Bn254Fr::from_canonical_usize(x))))
            .collect::<Vec<_>>();

        for (index, expected_next_index) in indices.iter().zip(expected_indices) {
            let index_bits = builder.num2bits_v_circuit(*index, 3);
            let next_index_bits = super::next_index_in_coset(&mut builder, index_bits);
            let next_index = builder.bits2num_v_circuit(&next_index_bits);
            builder.assert_var_eq(
                SymbolicVar::from_f(Bn254Fr::from_canonical_usize(expected_next_index)),
                next_index,
            );
        }

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }
}
