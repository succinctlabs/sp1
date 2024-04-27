use std::{
    fs::{self, File},
    io::Read,
};

use sp1_core::{
    air::{MachineAir, Word},
    io::SP1Stdin,
    runtime::{Program, Runtime},
    stark::{Dom, ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey, Val},
};
use sp1_recursion_program::{stark::EMPTY, types::QuotientDataValues};

use crate::SP1CoreProof;

impl SP1CoreProof {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

pub fn get_chip_quotient_data<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &StarkMachine<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<QuotientDataValues> {
    machine
        .shard_chips_ordered(&proof.chip_ordering)
        .map(|chip| {
            let log_quotient_degree = chip.log_quotient_degree();
            QuotientDataValues {
                log_quotient_degree,
                quotient_size: 1 << log_quotient_degree,
            }
        })
        .collect()
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &SP1Stdin) -> u64 {
    let program = Program::from(elf);
    let mut runtime = Runtime::new(program);
    runtime.write_vecs(&stdin.buffer);
    runtime.run();
    runtime.state.global_clk
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &StarkMachine<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<usize> {
    println!("{:?}", proof.chip_ordering);
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

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    return words.iter().flat_map(|word| word.0).collect();
}
