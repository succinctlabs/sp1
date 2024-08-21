use itertools::{izip, Itertools};
use p3_baby_bear::BabyBear;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Felt, SymbolicExt, SymbolicFelt};
use std::{
    cmp::Reverse,
    iter::{once, repeat_with, zip},
};

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
    challenger: &mut SC::FriChallengerVariable,
) -> FriChallenges<C> {
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
    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Vec<C::Bit>> =
        repeat_with(|| challenger.sample_bits(builder, log_max_height))
            .take(config.num_queries)
            .collect();

    FriChallenges { query_indices, betas }
}

pub fn verify_two_adic_pcs<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &TwoAdicPcsProofVariable<C, SC>,
    challenger: &mut SC::FriChallengerVariable,
    rounds: Vec<TwoAdicPcsRoundVariable<C, SC>>,
) {
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges::<C, SC>(builder, config, &proof.fri_proof, challenger);

    let log_global_max_height = proof.fri_proof.commit_phase_commits.len() + config.log_blowup;

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<C::F, C::EF>> =
        vec![builder.eval(SymbolicExt::from_f(C::EF::one()))];

    let reduced_openings = proof
        .query_openings
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, index_bits)| {
            // The powers of alpha, where the ith element is alpha^i.
            let mut log_height_pow = [0usize; 32];
            let mut ro: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::from_f(C::EF::zero())); 32];

            for (batch_opening, round) in zip(query_opening, rounds.iter().cloned()) {
                let batch_commit = round.batch_commit;
                let mats = round.domains_points_and_opens;
                let batch_heights =
                    mats.iter().map(|mat| mat.domain.size() << config.log_blowup).collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let reduced_index_bits = index_bits[bits_reduced..].to_vec();

                verify_batch::<C, SC>(
                    builder,
                    batch_commit,
                    batch_dims,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );

                for (mat_opening, mat) in izip!(&batch_opening.opened_values, mats) {
                    let mat_domain = mat.domain;
                    let mat_points = mat.points;
                    let mat_values = mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let reduced_index_bits_trunc =
                        index_bits[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();
                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        C::exp_reverse_bits(builder, two_adic_generator, reduced_index_bits_trunc);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        // builder.cycle_tracker("2adic-hotloop");
                        let mut acc: Ext<C::F, C::EF> =
                            builder.eval(SymbolicExt::from_f(C::EF::zero()));
                        for (p_at_x, p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
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
                        ro[log_height] = builder.eval(ro[log_height] + acc / (z - x));
                        // builder.cycle_tracker("2adic-hotloop");
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

pub fn verify_challenges<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &FriProofVariable<C, SC>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for ((index_bits, query_proof), ro) in
        challenges.query_indices.iter().zip(&proof.query_proofs).zip(reduced_openings)
    {
        let folded_eval = verify_query::<C, SC>(
            builder,
            proof.commit_phase_commits.clone(),
            index_bits,
            query_proof.clone(),
            challenges.betas.clone(),
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

pub fn verify_query<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<SC::Digest>,
    index_bits: &[C::Bit],
    proof: FriQueryProofVariable<C, SC>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<_, _> = builder.constant(C::EF::zero());
    let two_adic_generator: Felt<_> = builder.constant(C::F::two_adic_generator(log_max_height));

    let x_felt =
        C::exp_reverse_bits(builder, two_adic_generator, index_bits[..log_max_height].to_vec());
    let mut x: Ext<_, _> = builder.eval(SymbolicExt::one() * SymbolicFelt::from(x_felt));

    for (offset, log_folded_height, commit, step, beta) in izip!(
        0..,
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    ) {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let index_sibling_complement: C::Bit = index_bits[offset].clone();
        // let index_sibling_complement: Felt<_> = builder.constant(C::F::one());
        let index_pair = &index_bits[(offset + 1)..];

        builder.reduce_e(folded_eval);

        let evals_ext = C::select_chain_ef(
            builder,
            index_sibling_complement.clone(),
            once(folded_eval),
            once(step.sibling_value),
        );
        let evals_felt = vec![
            C::ext2felt(builder, evals_ext[0]).to_vec(),
            C::ext2felt(builder, evals_ext[1]).to_vec(),
        ];

        let dims = &[Dimensions { width: 2, height: (1 << log_folded_height) }];
        verify_batch::<C, SC>(
            builder,
            commit,
            dims.to_vec(),
            index_pair.to_vec(),
            [evals_felt].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new: Ext<_, _> = builder.eval(x * C::EF::two_adic_generator(1));
        let xs = C::select_chain_ef(builder, index_sibling_complement, once(x), once(xs_new));
        folded_eval = builder
            .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
        x = builder.eval(x * x);
    }

    folded_eval
}

pub fn verify_batch<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    commit: SC::Digest,
    dimensions: Vec<Dimensions>,
    index_bits: Vec<C::Bit>,
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

    zip(index_bits, proof).for_each(|(bit, sibling): (C::Bit, SC::Digest)| {
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
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable { sibling_value, opening_proof }
                    })
                    .collect::<Vec<_>>();
                FriQueryProofVariable { commit_phase_openings }
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
            index_bits,
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
    fn test_verify_two_adic_pcs_inner() {
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
