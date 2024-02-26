use core::marker::PhantomData;

use sp1_core::air::MachineAir;
use sp1_core::stark::{RiscvStark, ShardProof, StarkGenericConfig, Verifier};

pub use sp1_core::*;

pub struct RecursiveVerifier<SC: StarkGenericConfig>(PhantomData<SC>);

impl<SC: StarkGenericConfig> RecursiveVerifier<SC> {
    pub fn new() -> Self {
        RecursiveVerifier(PhantomData)
    }

    pub fn verify_shard(
        machine: &RiscvStark<SC>,
        challenger: &mut SC::Challenger,
        proof: &ShardProof<SC>,
    ) {
        let shard_chips = machine
            .chips()
            .iter()
            .filter(|chip| proof.chip_ids.contains(&chip.name()))
            .collect::<Vec<_>>();

        Verifier::verify_shard(machine.config(), &shard_chips, challenger, proof)
            .expect("verification failed")
    }
}

impl<SC: StarkGenericConfig> Default for RecursiveVerifier<SC> {
    fn default() -> Self {
        RecursiveVerifier::new()
    }
}
