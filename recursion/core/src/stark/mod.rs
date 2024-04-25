pub mod config;
pub mod poseidon2;
pub mod utils;

use crate::{
    cpu::CpuChip,
    fri_fold::FriFoldChip,
    memory::{MemoryChipKind, MemoryGlobalChip},
    poseidon2_wide::Poseidon2WideChip,
    program::ProgramChip,
    range_check::RangeCheckChip,
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
pub enum RecursionAirWideDeg3<F: PrimeField32 + BinomiallyExtendable<D>> {
    Program(ProgramChip),
    Cpu(CpuChip<F>),
    MemoryInit(MemoryGlobalChip),
    MemoryFinalize(MemoryGlobalChip),
    // Poseidon2(Poseidon2WideChip),
    FriFold(FriFoldChip),
    RangeCheck(RangeCheckChip<F>),
}

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::runtime::ExecutionRecord<F>"]
#[program_path = "crate::runtime::RecursionProgram<F>"]
#[builder_path = "crate::air::SP1RecursionAirBuilder<F = F>"]
pub enum RecursionAirSkinnyDeg7<F: PrimeField32 + BinomiallyExtendable<D>> {
    Program(ProgramChip),
    Cpu(CpuChip<F>),
    MemoryInit(MemoryGlobalChip),
    MemoryFinalize(MemoryGlobalChip),
    Poseidon2(Poseidon2WideChip),
    FriFold(FriFoldChip),
    RangeCheck(RangeCheckChip<F>),
    // Poseidon2(Poseidon2Chip),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> RecursionAirWideDeg3<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn get_all() -> Vec<Self> {
        once(RecursionAirWideDeg3::Program(ProgramChip))
            .chain(once(RecursionAirWideDeg3::Cpu(CpuChip::default())))
            .chain(once(RecursionAirWideDeg3::MemoryInit(MemoryGlobalChip {
                kind: MemoryChipKind::Init,
            })))
            .chain(once(RecursionAirWideDeg3::MemoryFinalize(
                MemoryGlobalChip {
                    kind: MemoryChipKind::Finalize,
                },
            )))
            // .chain(once(RecursionAirWideDeg3::Poseidon2(Poseidon2WideChip {})))
            .chain(once(RecursionAirWideDeg3::FriFold(FriFoldChip {})))
            .chain(once(RecursionAirWideDeg3::RangeCheck(
                RangeCheckChip::default(),
            )))
            .collect()
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> RecursionAirSkinnyDeg7<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn get_all() -> Vec<Self> {
        once(RecursionAirSkinnyDeg7::Program(ProgramChip))
            .chain(once(RecursionAirSkinnyDeg7::Cpu(CpuChip::default())))
            .chain(once(RecursionAirSkinnyDeg7::MemoryInit(MemoryGlobalChip {
                kind: MemoryChipKind::Init,
            })))
            .chain(once(RecursionAirSkinnyDeg7::MemoryFinalize(
                MemoryGlobalChip {
                    kind: MemoryChipKind::Finalize,
                },
            )))
            // .chain(once(RecursionAirSkinnyDeg7::Poseidon2(
            //     Poseidon2WideChip {},
            // )))
            .chain(once(RecursionAirSkinnyDeg7::FriFold(FriFoldChip {})))
            .chain(once(RecursionAirSkinnyDeg7::RangeCheck(
                RangeCheckChip::default(),
            )))
            .collect()
    }
}
