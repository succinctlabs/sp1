use itertools::Itertools;
use p3_field::AbstractField;
use p3_matrix::Dimensions;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt},
};
use std::{cmp::Reverse, iter::zip};

use crate::DigestVariable;

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
        builder.assert_felt_eq(bit * cobit, C::F::zero()); // Is this line needed?

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

    for (e1, e2) in zip(root, commit) {
        builder.assert_felt_eq(e1, e2);
    }
}
