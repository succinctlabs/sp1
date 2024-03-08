use crate::{cpu::CpuChip, program::ProgramChip};
use p3_field::PrimeField32;
use sp1_core::stark::{Chip, MachineStark, StarkGenericConfig};
use sp1_derive::MachineAir;

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::runtime::ExecutionRecord<F>"]
pub enum RecursionAir<F: PrimeField32> {
    Cpu(CpuChip<F>),
    Program(ProgramChip),
}

#[allow(dead_code)]
impl<F: PrimeField32> RecursionAir<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> MachineStark<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        MachineStark::new(config, chips)
    }

    pub fn get_all() -> Vec<Self> {
        let mut chips = vec![];
        let cpu = CpuChip::default();
        chips.push(RecursionAir::Cpu(cpu));
        let program = ProgramChip;
        chips.push(RecursionAir::Program(program));
        chips
    }
}
