//! Given an ethereum beacon root, a start slot, an end slot, and an eigenpod address, returns the
//! sum of all beacon partial withdrawals in [start_slot, end_slot) to the given eigenpod address.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod beacon;

use beacon::hints;
use beacon::prove;
use beacon::types::*;
use beacon::utils::node_from_bytes;
use hex_literal::hex;
use ssz_rs::prelude::*;
use std::collections::HashMap;

pub fn main() {
    // Get inputs.
    let beacon_block_root =
        node_from_bytes(hex!("d00c4da1a3ad4d42bd35f128544227d19e163194569d69d54a3d14112e3c897c"));
    let start_slot = 7855804;
    let end_slot = 7855807;
    let eigenpod_address =
        ExecutionAddress::try_from(hex!("e9cd1419a015dd05d47f6139f5b8e86b1e9e5cdd").to_vec())
            .unwrap();

    // Get slot number from block by proving the block header.
    let source_slot = prove::block_header(beacon_block_root).slot;

    // Load the witness data from outside of the vm.
    let (withdrawal_slots, validator_indexes) =
        hints::withdrawals_range(beacon_block_root, start_slot, end_slot, &eigenpod_address);

    // For all validator_indexes in the range, prove their withdrawable epoch so we can check
    // whether each withdrawal is partial or full.
    let validators_root = prove::validators_root(beacon_block_root);
    let mut withdrawable_epochs = HashMap::<u64, u64>::new();
    for validator_index in validator_indexes {
        println!("validator index: {}", validator_index);
        let validator = prove::validator(beacon_block_root, validators_root, validator_index);
        withdrawable_epochs.insert(validator_index, validator.withdrawable_epoch);
    }

    // Compute the sum of all partial withdrawals.
    let mut sum = 0;
    for (slot, withdrawal_indexes) in withdrawal_slots {
        let historical_block_root =
            prove::historical_block_root(beacon_block_root, source_slot, slot);
        let withdrawals_root = prove::withdrawals_root(historical_block_root);
        let epoch = slot / 32;
        for index in withdrawal_indexes {
            let withdrawal = prove::withdrawal(historical_block_root, withdrawals_root, index);

            let withdrawable_epoch = withdrawable_epochs.get(&withdrawal.validator_index).unwrap();
            if epoch < *withdrawable_epoch {
                sum += withdrawal.amount;
            }
        }
    }

    println!("sum: {}", sum);
}
