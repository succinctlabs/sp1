use std::fs;

use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, TwoAdicField};
use sp1_core::{
    air::MachineAir,
    stark::{Dom, ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey, Val},
};
use sp1_primitives::poseidon2_hash;
use sp1_recursion_circuit::DIGEST_SIZE;
use sp1_recursion_program::stark::EMPTY;

use crate::{CoreSC, SP1CoreProof, SP1VerifyingKey};

impl SP1CoreProof {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

pub fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &StarkMachine<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<usize> {
    machine
        .chips_sorted_indices(proof)
        .into_iter()
        .map(|x| match x {
            Some(x) => x,
            None => EMPTY,
        })
        .collect()
}

pub fn get_preprocessed_data<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &StarkMachine<SC, A>,
    vk: &StarkVerifyingKey<SC>,
) -> (Vec<usize>, Vec<Dom<SC>>) {
    let chips = machine.chips();
    let (prep_sorted_indices, prep_domains) = machine
        .preprocessed_chip_ids()
        .into_iter()
        .map(|chip_idx| {
            let name = chips[chip_idx].name().clone();
            let prep_sorted_idx = vk.chip_ordering[&name];
            (prep_sorted_idx, vk.chip_information[prep_sorted_idx].1)
        })
        .unzip();
    (prep_sorted_indices, prep_domains)
}

/// Hash the verifying key + prep domains into a single digest.
/// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
pub fn hash_vkey<A: MachineAir<BabyBear>>(
    machine: &StarkMachine<CoreSC, A>,
    vkey: &SP1VerifyingKey,
) -> [BabyBear; 8] {
    // TODO: cleanup
    let (_, prep_domains) = get_preprocessed_data(machine, &vkey.vk);
    let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
    let mut inputs = Vec::with_capacity(num_inputs);
    inputs.extend(vkey.vk.commit.as_ref());
    inputs.push(vkey.vk.pc_start);
    for domain in prep_domains.iter() {
        inputs.push(BabyBear::from_canonical_usize(domain.log_n));
        let size = 1 << domain.log_n;
        inputs.push(BabyBear::from_canonical_usize(size));
        let g = BabyBear::two_adic_generator(domain.log_n);
        inputs.push(domain.shift);
        inputs.push(g);
    }

    println!("vkey hash inputs: {:?}", inputs);
    poseidon2_hash(inputs)
}
