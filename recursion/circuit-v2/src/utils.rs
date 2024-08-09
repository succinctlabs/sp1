use sp1_core::{
    air::MachineAir,
    stark::{ShardProof, StarkGenericConfig, StarkMachine},
};
use sp1_recursion_program::types::QuotientDataValues;

use crate::stark::EMPTY;

pub(crate) fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
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

pub(crate) fn get_chip_quotient_data<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
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
