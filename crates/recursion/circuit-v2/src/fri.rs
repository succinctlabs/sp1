use ff::derive::bitvec::index;
use itertools::{izip, Itertools};
use p3_baby_bear::BabyBear;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config, Felt, SymbolicExt, SymbolicFelt};
use std::{
    cmp::Reverse,
    iter::{repeat_with, zip},
};

use crate::{
    challenger::CanSampleBitsVariable, utils::access_index_with_var_e,
    FriCommitPhaseProofStepVariable, NormalizeQueryProofVariable,
};
use crate::{challenger::FieldChallengerVariable, BabyBearFriConfigVariable};
use crate::{
    challenger::{CanSampleBitsVariable, FieldChallengerVariable},
    BabyBearFriConfigVariable, CanObserveVariable, CircuitConfig, Ext, FriChallenges, FriMmcs,
    FriProofVariable, FriQueryProofVariable, TwoAdicPcsProofVariable, TwoAdicPcsRoundVariable,
};

pub fn verify_shape_and_sample_challenges<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &FriProofVariable<C, SC>,
    log_max_height: usize,
    challenger: &mut SC::FriChallengerVariable,
) -> FriChallenges<C> {
    let normalize_betas = proof
        .normalize_phase_commits
        .iter()
        .map(|commitment| {
            challenger.observe(builder, *commitment);
            challenger.sample_ext(builder)
        })
        .collect();

    let betas = proof
        .commit_phase_commits
        .iter()
        .map(|commitment| {
            challenger.observe(builder, *commitment);
            challenger.sample_ext(builder)
        })
        .collect();

    // Observe the final polynomial.
    let final_poly_felts = C::ext2felt(builder, proof.final_poly);
    final_poly_felts.iter().for_each(|felt| {
        challenger.observe(builder, *felt);
    });

    assert_eq!(proof.query_proofs.len(), config.num_queries);
    assert_eq!(proof.normalize_query_proofs.len(), config.num_queries);

    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let query_indices: Vec<Vec<C::Bit>> =
        repeat_with(|| challenger.sample_bits(builder, log_max_height))
            .take(config.num_queries)
            .collect();

    FriChallenges { query_indices, betas, normalize_betas }
}

pub fn verify_two_adic_pcs<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &TwoAdicPcsProofVariable<C, SC>,
    challenger: &mut SC::FriChallengerVariable,
    rounds: Vec<TwoAdicPcsRoundVariable<C, SC>>,
) {
    let alpha = challenger.sample_ext(builder);

    let log_global_max_height = log2_strict_usize(
        rounds
            .iter()
            .map(|round| {
                round
                    .domains_points_and_opens
                    .iter()
                    .map(|dpo| dpo.domain.size() << config.log_blowup)
                    .max()
                    .unwrap()
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
        .map(|(query_opening, index)| {
            let index = index.clone();
            let mut ro: [Option<Ext<C::F, C::EF>>; 32] = [None; 32];
            // An array of the current power for each log_height.
            let mut log_height_pow = [0usize; 32];

            for (batch_opening, round) in izip!(query_opening.clone(), &rounds) {
                let batch_commit = round.batch_commit;
                let dop = &round.domains_points_and_opens;
                let batch_heights =
                    dop.iter().map(|mat| mat.domain.size() << config.log_blowup).collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                // Should have length `log_batch_max_height`.
                let reduced_index_bits = index[bits_reduced..].to_vec();

                verify_batch::<C, SC>(
                    builder,
                    batch_commit,
                    batch_dims,
                    &reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );
                for (mat_opening, mat) in izip!(batch_opening.opened_values.clone(), dop) {
                    let mat_domain = mat.domain;
                    let mat_points = &mat.points;
                    let mat_values = &mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    // Should have length `log_height`, but we enforce this anyway.
                    let reduced_index_bits =
                        index[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();

                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        C::exp_reverse_bits(builder, two_adic_generator, reduced_index_bits);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        let mut acc: Ext<C::F, C::EF> =
                            builder.eval(SymbolicExt::from_f(C::EF::zero()));
                        for (p_at_x, &p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let pow = log_height_pow[log_height];
                            // Fill in any missing powers of alpha.
                            (alpha_pows.len()..pow + 1).for_each(|_| {
                                let new_alpha = builder.eval(*alpha_pows.last().unwrap() * alpha);
                                // builder.reduce_e(new_alpha);
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
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();

    verify_challenges::<C, SC>(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        reduced_openings,
    );
}

#[allow(clippy::type_complexity)]
pub fn verify_challenges<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &FriProofVariable<C, SC>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Option<Ext<C::F, C::EF>>; 32]>,
) {
    let log_max_normalized_height =
        config.log_arity * proof.commit_phase_commits.len() + config.log_blowup;

    let log_max_height =
        reduced_openings[0].iter().enumerate().filter_map(|(i, v)| v.map(|_| i)).max().unwrap();

    for (index, query_proof, normalize_query_proof, ro) in izip!(
        challenges.query_indices.iter(),
        &proof.query_proofs.clone(),
        &proof.normalize_query_proofs.clone(),
        reduced_openings
    ) {
        let normalized_openings = verify_normalization_phase(
            builder,
            config,
            proof.normalize_phase_commits.clone(),
            index,
            normalize_query_proof,
            &challenges.normalize_betas,
            &ro,
            log_max_height,
        );

        let new_index_bits = index[log_max_height - log_max_normalized_height..].to_vec();

        let folded_eval = verify_query(
            builder,
            config,
            proof.commit_phase_commits.clone(),
            new_index_bits,
            query_proof.clone(),
            challenges.betas.clone(),
            normalized_openings,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

fn verify_normalization_phase<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    normalize_phase_commits: Vec<SC::Digest>,
    index_bits: &[C::Bit],
    normalize_proof: &NormalizeQueryProofVariable<C, SC>,
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

    let x = C::exp_reverse_bits(builder, generator, index_bits.to_vec());

    for (commit, log_height, step, beta) in izip!(
        normalize_phase_commits.into_iter(),
        heights,
        &normalize_proof.normalize_phase_openings,
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

        let new_index = C::bits2num(builder, index_bits[(log_max_height - log_height)..].to_vec());
        let new_index_bits = C::num2bits(builder, new_index, log_max_height);

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
            &new_index_bits,
            log_height - num_folds,
            xs,
        );
        new_openings[log_folded_height] = builder.eval(new_openings[log_folded_height] + fold_add);
    }

    new_openings
}

pub fn verify_query<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    commit_phase_commits: Vec<SC::Digest>,
    mut index_bits: Vec<C::Bit>,
    proof: FriQueryProofVariable<C, SC>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
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

    // index_bits should have length `log_max_normalized_height`.
    let mut x = C::exp_reverse_bits(builder, two_adic_generator, index_bits.to_vec());

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
            &step,
            commit,
            &index_bits,
            log_folded_height,
            xs,
        );
        let new_index = C::bits2num(builder, index_bits[(i + 1) * config.log_arity..].to_vec());
        index_bits = C::num2bits(builder, new_index, log_max_normalized_height);
        x = builder.exp_power_of_2(x, config.log_arity);

        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height]);
    }

    folded_eval
}

fn verify_fold_step<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    folded_eval: Ext<C::F, C::EF>,
    beta: Ext<C::F, C::EF>,
    num_folds: usize,
    step: &FriCommitPhaseProofStepVariable<C, SC>,
    commit: SC::Digest,
    index: &[C::Bit],
    log_folded_height: usize,
    xs: Vec<Felt<C::F>>,
) -> Ext<C::F, C::EF> {
    let index_num = C::bits2num(builder, index.to_vec());
    let index = C::num2bits(builder, index_num, log_folded_height);
    let index_self_in_siblings = index[..num_folds].to_vec();
    let index_set = &index[num_folds..];

    let evals: Vec<Ext<C::F, C::EF>> = step.siblings.clone();
    let expected_eval = access_index_with_var_e(builder, &evals, index_self_in_siblings.clone());
    builder.assert_ext_eq(expected_eval, folded_eval);

    let evals_felt: Vec<Vec<Felt<<C as Config>::F>>> =
        evals.iter().map(|eval| builder.ext2felt_circuit(*eval).to_vec()).collect();

    let dims = &[Dimensions { width: (1 << num_folds), height: (1 << log_folded_height) }];
    verify_batch::<C, SC>(
        builder,
        commit,
        dims.to_vec(),
        index_set,
        [evals_felt].to_vec(),
        step.opening_proof.clone(),
    );

    let mut ord_idx_bits = index_self_in_siblings;
    let mut ord_evals: Vec<Ext<_, _>> = vec![];

    for _ in 0..(1 << num_folds) {
        let new_eval = access_index_with_var_e(builder, &evals, ord_idx_bits.clone());
        ord_evals.push(new_eval);
        ord_idx_bits = next_index_in_coset(builder, ord_idx_bits);
    }

    interpolate_fft_and_evaluate(builder, &xs, &ord_evals, beta)
}

fn next_index_in_coset<C: CircuitConfig>(
    builder: &mut Builder<C>,
    index: Vec<C::Bit>,
) -> Vec<C::Bit> {
    // TODO better names.
    let len = index.len();
    let rev_bits = C::reverse_bits_len(builder, &index, len);
    let index = C::bits2num(builder, rev_bits);
    let index_plus_one = builder.eval(index + C::F::one());
    let index_plus_one_bits = C::num2bits(builder, index_plus_one, len);
    C::reverse_bits_len(builder, &index_plus_one_bits, len)
}

// Inefficient algorithm for interpolation and evaluation of a polynomial at a point.
fn interpolate_fft_and_evaluate<C: CircuitConfig>(
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
    // builder.reduce_e(odd_result);
    // builder.reduce_e(even_result);
    builder.eval(even_result + beta * odd_result)
}

pub fn verify_batch<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    commit: SC::Digest,
    dimensions: Vec<Dimensions>,
    index_bits: &[C::Bit],
    opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    proof: Vec<SC::Digest>,
) {
    let mut heights_tallest_first =
        dimensions.iter().enumerate().sorted_by_key(|(_, dims)| Reverse(dims.height)).peekable();

    let mut curr_height_padded = heights_tallest_first.peek().unwrap().1.height.next_power_of_two();

    let ext_slice: Vec<Vec<Felt<C::F>>> = heights_tallest_first
        .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height_padded)
        .flat_map(|(i, _)| opened_values[i].as_slice())
        .cloned()
        .collect::<Vec<_>>();
    let felt_slice: Vec<Felt<C::F>> =
        ext_slice.iter().flat_map(|ext| ext.as_slice()).cloned().collect::<Vec<_>>();
    let mut root: SC::Digest = SC::hash(builder, &felt_slice[..]);

    zip(index_bits, proof).for_each(|(&bit, sibling): (&C::Bit, SC::Digest)| {
        let compress_args = SC::select_chain_digest(builder, bit, [root, sibling]);

        root = SC::compress(builder, compress_args);
        curr_height_padded >>= 1;

        let next_height = heights_tallest_first
            .peek()
            .map(|(_, dims)| dims.height)
            .filter(|h| h.next_power_of_two() == curr_height_padded);

        if let Some(next_height) = next_height {
            let ext_slice: Vec<Vec<Felt<C::F>>> = heights_tallest_first
                .peeking_take_while(|(_, dims)| dims.height == next_height)
                .flat_map(|(i, _)| opened_values[i].as_slice())
                .cloned()
                .collect::<Vec<_>>();
            let felt_slice: Vec<Felt<C::F>> =
                ext_slice.iter().flat_map(|ext| ext.as_slice()).cloned().collect::<Vec<_>>();
            let next_height_openings_digest = SC::hash(builder, &felt_slice);
            root = SC::compress(builder, [root, next_height_openings_digest]);
        }
    });

    SC::assert_digest_eq(builder, root, commit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        challenger::DuplexChallengerVariable, utils::tests::run_test_recursion,
        BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
        FriQueryProofVariable, TwoAdicPcsMatsVariable, TwoAdicPcsProofVariable,
    };
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::AbstractField;
    use p3_fri::{verifier, TwoAdicFriPcsProof};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    };
    use sp1_recursion_compiler::{
        asm::AsmBuilder,
        config::InnerConfig,
        ir::{Builder, Ext, SymbolicExt},
    };
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, inner_fri_config, inner_perm, InnerChallenge,
        InnerChallengeMmcs, InnerChallenger, InnerCompress, InnerDft, InnerFriProof, InnerHash,
        InnerPcs, InnerVal, InnerValMmcs, StarkGenericConfig,
    };

    use sp1_recursion_core_v2::DIGEST_SIZE;

    use crate::Digest;

    type C = InnerConfig;
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    pub fn const_fri_proof(
        builder: &mut AsmBuilder<F, EF>,
        fri_proof: InnerFriProof,
    ) -> FriProofVariable<InnerConfig, SC> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [F; DIGEST_SIZE] = (*commit).into();
                commit.map(|x| builder.eval(x))
            })
            .collect::<Vec<_>>();

        let normalize_phase_commits = fri_proof
            .normalize_phase_commits
            .iter()
            .map(|commit| {
                let commit: [F; DIGEST_SIZE] = (*commit).into();
                commit.map(|x| builder.eval(x))
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
                        let siblings: Vec<Ext<_, _>> = commit_phase_opening
                            .siblings
                            .iter()
                            .map(|val| builder.eval(SymbolicExt::from_f(*val)))
                            .collect();
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
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
                    .map(|normalize_phase_opening| {
                        let siblings: Vec<Ext<_, _>> = normalize_phase_opening
                            .siblings
                            .iter()
                            .map(|val| builder.eval(SymbolicExt::from_f(*val)))
                            .collect();
                        let opening_proof = normalize_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
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
            query_proofs,
            normalize_query_proofs,
            final_poly: builder.eval(SymbolicExt::from_f(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    pub fn const_two_adic_pcs_proof(
        builder: &mut Builder<InnerConfig>,
        proof: TwoAdicFriPcsProof<InnerVal, InnerChallenge, InnerValMmcs, InnerChallengeMmcs>,
    ) -> TwoAdicPcsProofVariable<InnerConfig, SC> {
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
                                    .map(|value| vec![builder.eval::<Felt<_>, _>(*value)])
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>(),
                        opening_proof: opening
                            .opening_proof
                            .iter()
                            .map(|opening_proof| opening_proof.map(|x| builder.eval(x)))
                            .collect::<Vec<_>>(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        TwoAdicPcsProofVariable { fri_proof, query_openings }
    }

    #[allow(clippy::type_complexity)]
    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<InnerConfig>,
        commit: [F; DIGEST_SIZE],
        os: Vec<(TwoAdicMultiplicativeCoset<InnerVal>, Vec<(InnerChallenge, Vec<InnerChallenge>)>)>,
    ) -> (Digest<InnerConfig, SC>, Vec<TwoAdicPcsRoundVariable<InnerConfig, SC>>) {
        let commit: Digest<InnerConfig, SC> = commit.map(|x| builder.eval(x));

        let mut domains_points_and_opens = Vec::new();
        for (domain, poly) in os.into_iter() {
            let points: Vec<Ext<InnerVal, InnerChallenge>> =
                poly.iter().map(|(p, _)| builder.eval(SymbolicExt::from_f(*p))).collect::<Vec<_>>();
            let values: Vec<Vec<Ext<InnerVal, InnerChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::from_f(*t)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let domain_points_and_values = TwoAdicPcsMatsVariable { domain, points, values };
            domains_points_and_opens.push(domain_points_and_values);
        }

        (commit, vec![TwoAdicPcsRoundVariable { batch_commit: commit, domains_points_and_opens }])
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L421
    #[test]
    fn size_gaps() {
        use p3_commit::Mmcs;
        let perm = inner_perm();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm);
        let mmcs = InnerValMmcs::new(hash, compress);

        let mut builder = Builder::<InnerConfig>::default();

        // 4 mats with 1000 rows, 8 columns
        let large_mats = (0..4).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 1000, 8));
        let large_mat_dims = (0..4).map(|_| Dimensions { height: 1000, width: 8 });

        // 5 mats with 70 rows, 8 columns
        let medium_mats = (0..5).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 70, 8));
        let medium_mat_dims = (0..5).map(|_| Dimensions { height: 70, width: 8 });

        // 6 mats with 8 rows, 8 columns
        let small_mats = (0..6).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 8, 8));
        let small_mat_dims = (0..6).map(|_| Dimensions { height: 8, width: 8 });

        let (commit, prover_data) =
            mmcs.commit(large_mats.chain(medium_mats).chain(small_mats).collect_vec());

        let commit: [_; DIGEST_SIZE] = commit.into();
        let commit = commit.map(|x| builder.eval(x));
        // open the 6th row of each matrix and verify
        let (opened_values, proof) = mmcs.open_batch(6, &prover_data);
        let opened_values = opened_values
            .into_iter()
            .map(|x| x.into_iter().map(|y| vec![builder.eval::<Felt<_>, _>(y)]).collect())
            .collect();
        let index = builder.eval(F::from_canonical_u32(6));
        let index_bits = C::num2bits(&mut builder, index, 32);
        let proof = proof.into_iter().map(|p| p.map(|x| builder.eval(x))).collect();
        verify_batch::<_, SC>(
            &mut builder,
            commit,
            large_mat_dims.chain(medium_mat_dims).chain(small_mat_dims).collect_vec(),
            &index_bits,
            opened_values,
            proof,
        );
    }

    #[test]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let log_blowup = fri_config.log_blowup;
        let pcs: InnerPcs =
            InnerPcs::new(log_degrees.iter().copied().max().unwrap(), dft, val_mmcs, fri_config);

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = repeat_with(|| vec![zeta]).take(domains_and_polys.len()).collect::<Vec<_>>();
        let (_, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let _: InnerChallenge = challenger.sample();
        let fri_challenges_gt = verifier::verify_shape_and_sample_challenges(
            &inner_fri_config(),
            &proof.fri_proof,
            log_degrees.iter().max().unwrap() + log_blowup,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = inner_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let commit: [_; DIGEST_SIZE] = commit.into();
        let commit: [Felt<InnerVal>; DIGEST_SIZE] = commit.map(|x| builder.eval(x));
        challenger.observe_slice(&mut builder, commit);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges = verify_shape_and_sample_challenges::<InnerConfig, BabyBearPoseidon2>(
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

        for i in 0..fri_challenges_gt.query_indices.len() {
            let query_indices =
                C::bits2num(&mut builder, fri_challenges.query_indices[i].iter().cloned());
            builder.assert_felt_eq(
                F::from_canonical_usize(fri_challenges_gt.query_indices[i]),
                query_indices,
            );
        }

        run_test_recursion(builder.operations, None);
    }

    #[test]
    fn test_verify_two_adic_pcs() {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let log_degrees = &[19, 19];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let pcs: InnerPcs =
            InnerPcs::new(log_degrees.iter().copied().max().unwrap(), dft, val_mmcs, fri_config);

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 100),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = domains_and_polys.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let x1 = challenger.sample_ext_element::<InnerChallenge>();
        let os = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect::<Vec<_>>();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger).unwrap();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = inner_fri_config();
        let proof = const_two_adic_pcs_proof(&mut builder, proof);
        let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        challenger.observe_slice(&mut builder, commit);
        let x2 = challenger.sample_ext(&mut builder);
        let x1: Ext<_, _> = builder.constant(x1);
        builder.assert_ext_eq(x1, x2);
        verify_two_adic_pcs::<_, BabyBearPoseidon2>(
            &mut builder,
            &config,
            &proof,
            &mut challenger,
            rounds,
        );

        run_test_recursion(builder.operations, std::iter::empty());
    }
}
