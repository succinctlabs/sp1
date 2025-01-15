use crate::beacon::hints;
use crate::beacon::types::*;
use crate::beacon::utils::is_valid_merkle_big_branch;
use ssz_rs::prelude::*;
use std::hint::black_box;
use std::str::FromStr;

pub fn block_header(block_root: Node) -> BeaconBlockHeader {
    black_box(hints::beacon_header_proof(block_root))
}

pub fn withdrawals_root(block_root: Node) -> Node {
    let (leaf, branch) = black_box(hints::withdrawals_root_proof(block_root));
    let depth = 11;
    let index = alloy_primitives::U256::from(3230);

    let valid =
        black_box(is_valid_merkle_big_branch(&leaf, branch.iter(), depth, index, &block_root));
    println!("withdrawals root valid: {}", valid);
    leaf
}

pub fn withdrawal(block_root: Node, withdrawals_root: Node, index: u32) -> Withdrawal {
    let (mut withdrawal, branch) = black_box(hints::withdrawal_proof(block_root, index));
    let leaf = withdrawal.hash_tree_root().unwrap();
    let depth = 5;
    let index = alloy_primitives::U256::from(32);

    let valid = black_box(is_valid_merkle_big_branch(
        &leaf,
        branch.iter(),
        depth,
        index,
        &withdrawals_root,
    ));
    println!("withdrawal valid: {}", valid);
    withdrawal
}

pub fn validators_root(block_root: Node) -> Node {
    let (leaf, branch) = black_box(hints::validators_root_proof(block_root));
    let depth = 8;
    let index = alloy_primitives::U256::from(363);
    let valid =
        black_box(is_valid_merkle_big_branch(&leaf, branch.iter(), depth, index, &block_root));
    println!("validators root valid: {}", valid);
    leaf
}

pub fn validator(block_root: Node, validators_root: Node, validator_index: u64) -> Validator {
    let (mut validator, branch) = black_box(hints::validator_proof(block_root, validator_index));
    let leaf = validator.hash_tree_root().unwrap();
    let depth = 41;
    // ssz.phase0.Validators.getPathInfo([0]).gindex
    let index = alloy_primitives::U256::from_str("2199023255552")
        .unwrap()
        .wrapping_add(alloy_primitives::U256::from(validator_index));
    let valid =
        black_box(is_valid_merkle_big_branch(&leaf, branch.iter(), depth, index, &validators_root));
    println!("validator valid: {}", valid);
    validator
}

pub fn historical_far_slot(block_root: Node, target_slot: u64) -> Node {
    let (leaf, branch) = black_box(hints::historical_far_slot_proof(block_root, target_slot));
    let depth = 33;
    let array_index = (target_slot - 6209536) / 8192;
    let index = alloy_primitives::U256::from_str("12717129728")
        .unwrap()
        .wrapping_add(alloy_primitives::U256::from(array_index));

    let valid =
        black_box(is_valid_merkle_big_branch(&leaf, branch.iter(), depth, index, &block_root));
    println!("historical far slot valid: {}", valid);
    leaf
}

fn historical_far_slot_blockroot(block_root: Node, summary_root: Node, target_slot: u64) -> Node {
    let (leaf, branch) =
        black_box(hints::historical_far_slot_blockroot_proof(block_root, target_slot));
    let depth = 14;
    let array_index = (target_slot) % 8192;
    let index = alloy_primitives::U256::from(16384 + array_index);

    let valid =
        black_box(is_valid_merkle_big_branch(&leaf, branch.iter(), depth, index, &summary_root));
    println!("historical far slot blockroot valid: {}", valid);
    leaf
}

pub fn historical_block_root(block_root: Node, source_slot: u64, target_slot: u64) -> Node {
    if source_slot - target_slot < 8192 {
        unimplemented!()
    } else {
        let summary_root = historical_far_slot(block_root, target_slot);
        historical_far_slot_blockroot(block_root, summary_root, target_slot)
    }
}
