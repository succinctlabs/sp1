use itertools::{izip, Itertools};
use p3_commit::PolynomialSpace;
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt, SymbolicExt},
};
use std::{cmp::Reverse, iter::zip};

use crate::challenger::DuplexChallengerVariable;
use crate::*;

pub fn verify_shape_and_sample_challenges<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];

    for i in 0..proof.commit_phase_commits.len() {
        let commitment: [Felt<C::F>; DIGEST_SIZE] = proof.commit_phase_commits[i];
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
    let query_indices: Vec<Vec<Felt<_>>> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(builder, log_max_height))
        .collect();

    FriChallenges {
        query_indices,
        betas,
    }
}

pub fn verify_two_adic_pcs<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
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
        .map(|(query_opening, index_bits)| {
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
                    let reduced_index_bits_trunc =
                        index_bits[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();
                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        builder.exp_reverse_bits_v2(two_adic_generator, reduced_index_bits_trunc);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        let mut acc: Ext<C::F, C::EF> =
                            builder.eval(SymbolicExt::from_f(C::EF::zero()));
                        for (p_at_x, &p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let pow = log_height_pow[log_height];
                            // Fill in any missing powers of alpha.
                            (alpha_pows.len()..pow + 1).for_each(|_| {
                                alpha_pows.push(builder.eval(*alpha_pows.last().unwrap() * alpha));
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

pub fn verify_challenges<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for (index_bits, query_proof, ro) in izip!(
        &challenges.query_indices,
        &proof.query_proofs,
        reduced_openings
    ) {
        let folded_eval = verify_query(
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

pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<DigestVariable<C>>,
    index_bits: &[Felt<C::F>],
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<_, _> = builder.eval(SymbolicExt::from_f(C::EF::zero()));
    let two_adic_generator: Felt<_> = builder.eval(C::F::two_adic_generator(log_max_height));
    index_bits
        .iter()
        .for_each(|&bit| builder.assert_felt_eq(bit * bit, bit)); // Is this line needed?
    let mut x = builder.exp_reverse_bits_v2(two_adic_generator, index_bits.to_vec());

    for (offset, (log_folded_height, commit, step, beta)) in izip!(
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    )
    .enumerate()
    {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let one: Felt<_> = builder.eval(C::F::one());
        let index_sibling: Felt<_> = builder.eval(one - index_bits[offset]);
        let index_pair = &index_bits[(offset + 1)..];

        let evals_ext = {
            // TODO factor this out into a function
            let bit = index_sibling;
            let true_fst = folded_eval;
            let true_snd = step.sibling_value;

            let one: Felt<_> = builder.eval(C::F::one());
            let cobit: Felt<_> = builder.eval(one - bit);

            let true_branch = [true_fst, true_snd];
            let false_branch = [true_snd, true_fst];
            zip(true_branch, false_branch)
                .map(|(tx, fx)| builder.eval(tx * bit + fx * cobit))
                .collect::<Vec<_>>()
        };
        let evals_felt = evals_ext
            .iter()
            .map(|&x| builder.ext2felt_v2(x).to_vec())
            .collect::<Vec<_>>();

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

        let xs_new: Felt<_> = builder.eval(x * C::F::two_adic_generator(1));
        let xs: Vec<Felt<C::F>> = {
            // TODO factor this out into a function
            let bit = index_sibling;
            let true_fst = x;
            let true_snd = xs_new;

            let one: Felt<_> = builder.eval(C::F::one());
            let cobit: Felt<_> = builder.eval(one - bit);

            let true_branch = [true_fst, true_snd];
            let false_branch = [true_snd, true_fst];
            zip(true_branch, false_branch)
                .map(|(tx, fx)| builder.eval(tx * bit + fx * cobit))
                .collect::<Vec<_>>()
        };
        folded_eval = builder
            .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
        x = builder.eval(x * x);
    }

    folded_eval
}

pub fn verify_batch<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    commit: DigestVariable<C>,
    dimensions: Vec<Dimensions>,
    index_bits: Vec<Felt<C::F>>,
    opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    proof: Vec<DigestVariable<C>>,
) {
    let mut heights_tallest_first = dimensions
        .iter()
        .enumerate()
        .sorted_by_key(|(_, dims)| Reverse(dims.height))
        .peekable();

    let mut curr_height_padded = heights_tallest_first
        .peek()
        .unwrap()
        .1
        .height
        .next_power_of_two();

    let ext_slice: Vec<Vec<Felt<C::F>>> = heights_tallest_first
        .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height_padded)
        .flat_map(|(i, _)| opened_values[i].as_slice())
        .cloned()
        .collect::<Vec<_>>();
    let felt_slice: Vec<Felt<C::F>> = ext_slice
        .iter()
        .flat_map(|ext| ext.as_slice())
        .cloned()
        .collect::<Vec<_>>();
    let mut root = builder.poseidon2_hash_v2(&felt_slice);

    for (bit, sibling) in zip(index_bits, proof) {
        let one: Felt<_> = builder.eval(C::F::one());
        let cobit: Felt<_> = builder.eval(one - bit);

        let true_branch = sibling.into_iter().chain(root);
        let false_branch = root.into_iter().chain(sibling);
        let pre_root = zip(true_branch, false_branch)
            .map(|(tx, fx)| builder.eval(bit * tx + cobit * fx))
            .collect::<Vec<_>>();

        root = builder.poseidon2_compress_v2(pre_root);
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
            let felt_slice: Vec<Felt<C::F>> = ext_slice
                .iter()
                .flat_map(|ext| ext.as_slice())
                .cloned()
                .collect::<Vec<_>>();
            let next_height_openings_digest = builder.poseidon2_hash_v2(&felt_slice);
            root =
                builder.poseidon2_compress_v2(root.into_iter().chain(next_height_openings_digest));
        }
    }

    zip(root, commit).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
}
