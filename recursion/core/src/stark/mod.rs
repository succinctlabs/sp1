pub mod config;
pub mod poseidon2;
pub mod utils;

use crate::{
    cpu::CpuChip, fri_fold::FriFoldChip, memory::MemoryGlobalChip, multi::MultiChip,
    poseidon2::Poseidon2Chip, poseidon2_wide::Poseidon2WideChip, program::ProgramChip,
    range_check::RangeCheckChip,
};
use core::iter::once;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sp1_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_derive::RecursionMachineAir;
use std::marker::PhantomData;

use crate::runtime::D;

pub type RecursionAirWideDeg3<F> = RecursionAir<F, 3, 1>;
pub type RecursionAirSkinnyDeg9<F> = RecursionAir<F, 9, 1>;
pub type RecursionAirSkinnyDeg15<F> = RecursionAir<F, 15, 1>;

#[derive(RecursionMachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::runtime::ExecutionRecord<F>"]
#[program_path = "crate::runtime::RecursionProgram<F>"]
#[builder_path = "crate::air::SP1RecursionAirBuilder<F = F>"]
pub enum RecursionAir<
    F: PrimeField32 + BinomiallyExtendable<D>,
    const DEGREE: usize,
    const ROUND_CHUNK_SIZE: usize,
> {
    Program(ProgramChip),
    Cpu(CpuChip<F, DEGREE>),
    MemoryGlobal(MemoryGlobalChip),
    Poseidon2Wide(Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE>),
    Poseidon2Skinny(Poseidon2Chip),
    FriFold(FriFoldChip<DEGREE>),
    RangeCheck(RangeCheckChip<F>),
    Multi(MultiChip<DEGREE>),
}

impl<
        F: PrimeField32 + BinomiallyExtendable<D>,
        const DEGREE: usize,
        const ROUND_CHUNK_SIZE: usize,
        AB: p3_air::PairBuilder + crate::air::SP1RecursionAirBuilder<F = F>,
    > p3_air::Air<AB> for RecursionAir<F, DEGREE, ROUND_CHUNK_SIZE>
where
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            RecursionAir::Program(x) => <ProgramChip as p3_air::Air<AB>>::eval(x, builder),
            RecursionAir::Cpu(x) => <CpuChip<F, DEGREE> as p3_air::Air<AB>>::eval(x, builder),
            RecursionAir::MemoryGlobal(x) => {
                <MemoryGlobalChip as p3_air::Air<AB>>::eval(x, builder)
            }
            RecursionAir::Poseidon2Wide(x) => {
                <Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE> as p3_air::Air<AB>>::eval(x, builder)
            }
            RecursionAir::Poseidon2Skinny(x) => {
                <Poseidon2Chip as p3_air::Air<AB>>::eval(x, builder)
            }
            RecursionAir::FriFold(x) => <FriFoldChip<DEGREE> as p3_air::Air<AB>>::eval(x, builder),
            RecursionAir::RangeCheck(x) => <RangeCheckChip<F> as p3_air::Air<AB>>::eval(x, builder),
            RecursionAir::Multi(x) => <MultiChip<DEGREE> as p3_air::Air<AB>>::eval(x, builder),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<D>,
        const DEGREE: usize,
        const ROUND_CHUNK_SIZE: usize,
    > RecursionAir<F, DEGREE, ROUND_CHUNK_SIZE>
{
    /// A recursion machine that can have dynamic trace sizes.
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A recursion machine with fixed trace sizes tuned to work specifically for the wrap layer.
    pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_wrap_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A recursion machine with fixed trace sizes tuned to work specifically for the wrap layer.
    pub fn wrap_machine_dyn<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_wrap_dyn_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn get_all() -> Vec<Self> {
        once(RecursionAir::Program(ProgramChip))
            .chain(once(RecursionAir::Cpu(CpuChip {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::Poseidon2Wide(Poseidon2WideChip::<
                DEGREE,
                ROUND_CHUNK_SIZE,
            > {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::FriFold(FriFoldChip::<DEGREE> {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
            .collect()
    }

    pub fn get_wrap_dyn_all() -> Vec<Self> {
        once(RecursionAir::Program(ProgramChip))
            .chain(once(RecursionAir::Cpu(CpuChip {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: None,
            })))
            // .chain(once(RecursionAir::Multi(MultiChip {
            //     fixed_log2_rows: None,
            // })))
            .chain(once(RecursionAir::Poseidon2Wide(Poseidon2WideChip::<
                DEGREE,
                ROUND_CHUNK_SIZE,
            > {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::FriFold(FriFoldChip::<DEGREE> {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
            .collect()
    }

    pub fn get_wrap_all() -> Vec<Self> {
        once(RecursionAir::Program(ProgramChip))
            .chain(once(RecursionAir::Cpu(CpuChip {
                fixed_log2_rows: Some(20),
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: Some(19),
            })))
            .chain(once(RecursionAir::Poseidon2Wide(Poseidon2WideChip::<
                DEGREE,
                ROUND_CHUNK_SIZE,
            > {
                fixed_log2_rows: None,
            })))
            .chain(once(RecursionAir::FriFold(FriFoldChip::<DEGREE> {
                fixed_log2_rows: None,
                // .chain(once(RecursionAir::Multi(MultiChip {
                //     fixed_log2_rows: Some(20),
            })))
            .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
            .collect()
    }
}
