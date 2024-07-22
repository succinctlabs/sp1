use itertools::Itertools;
use p3_matrix::Dimensions;
use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};
use std::cmp::Reverse;

use crate::{poseidon2::Poseidon2CircuitBuilder, types::OuterDigestVariable};

pub fn verify_batch<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    commit: OuterDigestVariable<C>,
    dimensions: Vec<Dimensions>,
    index_bits: Vec<Var<C::N>>,
    opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    proof: Vec<OuterDigestVariable<C>>,
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
    let mut root = builder.p2_hash(&felt_slice);

    for (i, sibling) in proof.iter().enumerate() {
        let bit = index_bits[i];
        let left = [builder.select_v(bit, sibling[0], root[0])];
        let right = [builder.select_v(bit, root[0], sibling[0])];

        root = builder.p2_compress([left, right]);
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
            let next_height_openings_digest = builder.p2_hash(&felt_slice);
            root = builder.p2_compress([root, next_height_openings_digest]);
        }
    }

    builder.assert_var_eq(root[0], commit[0]);
}
