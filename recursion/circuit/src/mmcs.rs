use std::cmp::Reverse;

use itertools::Itertools;
use p3_matrix::Dimensions;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Ext, Var};

pub fn verify_batch<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    commit: &Array<C, Var<C::N>>,
    dimensions: &[Dimensions],
    index_bits: Array<C, Var<C::N>>,
    opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    proof: &Array<C, Array<C, Var<C::N>>>,
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

    // TODO: compute root

    todo!()

    // // The index of which table to process next.
    // let index: Var<C::N> = builder.eval(C::N::zero());

    // // The height of the current layer (padded).
    // let current_height = builder.get(&dimensions, index).height;

    // // Reduce all the tables that have the same height to a single root.
    // let root = reduce::<C, D>(builder, index, &dimensions, current_height, &opened_values);

    // // For each sibling in the proof, reconstruct the root.
    // let one: Var<_> = builder.eval(C::N::one());
    // builder.range(0, proof.len()).for_each(|i, builder| {
    //     let sibling = builder.get(proof, i);

    //     let bit = builder.get(&index_bits, i);
    //     let left: Array<C, Felt<C::F>> = builder.uninit();
    //     let right: Array<C, Felt<C::F>> = builder.uninit();
    //     builder.if_eq(bit, C::N::one()).then_or_else(
    //         |builder| {
    //             builder.assign(left.clone(), sibling.clone());
    //             builder.assign(right.clone(), root.clone());
    //         },
    //         |builder| {
    //             builder.assign(left.clone(), root.clone());
    //             builder.assign(right.clone(), sibling.clone());
    //         },
    //     );

    //     let new_root = builder.poseidon2_compress(&left, &right);
    //     builder.assign(root.clone(), new_root);
    //     builder.assign(current_height, current_height * (C::N::two().inverse()));

    //     let next_height = builder.get(&dimensions, index).height;
    //     builder.if_ne(index, dimensions.len()).then(|builder| {
    //         builder.if_eq(next_height, current_height).then(|builder| {
    //             let next_height_openings_digest =
    //                 reduce::<C, D>(builder, index, &dimensions, current_height, &opened_values);
    //             let new_root = builder.poseidon2_compress(&root, &next_height_openings_digest);
    //             builder.assign(root.clone(), new_root);
    //         });
    //     })
    // });

    // // Assert that the commitments match.
    // builder.range(0, commit.len()).for_each(|i, builder| {
    //     let e1 = builder.get(commit, i);
    //     let e2 = builder.get(&root, i);
    //     builder.assert_felt_eq(e1, e2);
    // });
}
