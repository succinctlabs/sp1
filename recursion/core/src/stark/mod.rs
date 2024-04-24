pub mod outer;
pub mod poseidon2;

use crate::{
    cpu::CpuChip,
    fri_fold::FriFoldChip,
    memory::{MemoryChipKind, MemoryGlobalChip},
    poseidon2_wide::Poseidon2WideChip,
    program::ProgramChip,
};
use core::iter::once;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_derive::MachineAir;

use crate::runtime::D;

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::runtime::ExecutionRecord<F>"]
#[program_path = "crate::runtime::RecursionProgram<F>"]
#[builder_path = "crate::air::SP1RecursionAirBuilder<F = F>"]
pub enum RecursionAirWide<F: PrimeField32 + BinomiallyExtendable<D>> {
    Program(ProgramChip),
    Cpu(CpuChip<F>),
    MemoryInit(MemoryGlobalChip),
    MemoryFinalize(MemoryGlobalChip),
    // Poseidon2(Poseidon2WideChip),
    FriFold(FriFoldChip),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> RecursionAirWide<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn get_all() -> Vec<Self> {
        once(RecursionAirWide::Program(ProgramChip))
            .chain(once(RecursionAirWide::Cpu(CpuChip::default())))
            .chain(once(RecursionAirWide::MemoryInit(MemoryGlobalChip {
                kind: MemoryChipKind::Init,
            })))
            .chain(once(RecursionAirWide::MemoryFinalize(MemoryGlobalChip {
                kind: MemoryChipKind::Finalize,
            })))
            // .chain(once(RecursionAirWide::Poseidon2(Poseidon2WideChip {})))
            .chain(once(RecursionAirWide::FriFold(FriFoldChip {})))
            .collect()
    }
}
