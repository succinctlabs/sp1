use alloy_primitives::U256;
use sha2::{Digest, Sha256};
use ssz_rs::prelude::Node;
use std::ops::Div;

// From https://github.com/ralexstokes/ssz-rs/blob/main/ssz-rs/src/merkleization/proofs.rs
// Modified to use alloy_primitives::U256 instead of u64 for large gindex values
pub fn is_valid_merkle_big_branch<'a>(
    leaf: &Node,
    mut branch: impl Iterator<Item = &'a Node>,
    depth: usize,
    index: U256,
    root: &Node,
) -> bool {
    let mut value = *leaf;

    let mut hasher = Sha256::new();
    for i in 0..depth {
        let next_node = match branch.next() {
            Some(node) => node,
            None => return false,
        };
        // if (index / 2usize.pow(i as u32)) % 2 != 0 {
        if (index
            .div(alloy_primitives::U256::from(2).pow(alloy_primitives::U256::from(i)))
            .wrapping_rem(alloy_primitives::U256::from(2)))
            != alloy_primitives::U256::from(0)
        {
            hasher.update(next_node.as_ref());
            hasher.update(value.as_ref());
        } else {
            hasher.update(value.as_ref());
            hasher.update(next_node.as_ref());
        }
        value.as_mut().copy_from_slice(&hasher.finalize_reset());
    }
    value == *root
}
