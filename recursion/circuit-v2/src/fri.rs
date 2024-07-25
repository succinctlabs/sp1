use itertools::Itertools;
use p3_field::{AbstractField, TwoAdicField};
use p3_matrix::Dimensions;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt, SymbolicExt},
};
use std::{cmp::Reverse, iter::zip};

use crate::*;

pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<DigestVariable<C>>,
    index: Felt<C::F>,
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<_, _> = builder.eval(SymbolicExt::from_f(C::EF::zero()));
    let two_adic_generator: Felt<_> = builder.eval(C::F::two_adic_generator(log_max_height));
    let index_bits = builder.num2bits_v2_f(index, 32); // Magic number?
    index_bits
        .iter()
        .for_each(|&bit| builder.assert_felt_eq(bit * bit, bit)); // Is this line needed?
    let mut x = builder.exp_reverse_bits_v2(two_adic_generator, index_bits.clone());

    for (offset, (log_folded_height, commit, step, beta)) in itertools::izip!(
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
