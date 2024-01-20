use alloy_primitives::U256;
use sha2::{Digest, Sha256};
use ssz_rs::prelude::Node;
use std::ops::Div;

// From https://github.com/ralexstokes/ssz-rs/blob/main/ssz-rs/src/merkleization/proofs.rs
// Modified to use alloy_primitives::U256 instead of u64 for large gindex values
#[allow(dead_code)]
pub fn is_valid_merkle_big_branch<'a>(
    leaf: &Node,
    mut branch: impl Iterator<Item = &'a Node>,
    depth: usize,
    index: U256,
    root: &Node,
) -> bool {
    let mut value: [u8; 32] = leaf.as_ref().try_into().unwrap();

    let mut gindex = index;

    let mut hasher = Sha256::new();
    let two = U256::from(2);
    for _ in 0..depth {
        let next_node = match branch.next() {
            Some(node) => node,
            None => return false,
        };
        if gindex.bit(0) {
            hasher.update(next_node.as_ref());
            hasher.update(value.as_ref());
        } else {
            hasher.update(value.as_ref());
            hasher.update(next_node.as_ref());
        }
        gindex = gindex.div(two);
        value = hasher.finalize_reset().into();
    }
    let root: [u8; 32] = root.as_ref().try_into().unwrap();
    root == value
}
