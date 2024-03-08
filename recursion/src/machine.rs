use crate::air::CpuChip;
use p3_field::PrimeField32;
use sp1_core::stark::{Chip, MachineStark, StarkGenericConfig};
use sp1_derive::MachineAir;

#[allow(dead_code)]
#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
pub enum RecursionAir<F: PrimeField32> {
    Cpu(CpuChip<F>),
}

#[allow(dead_code)]
impl<F: PrimeField32> RecursionAir<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> MachineStark<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        MachineStark { config, chips }
    }

    pub fn get_all() -> Vec<Self> {
        let mut chips = vec![];
        let cpu = CpuChip::default();
        chips.push(RecursionAir::Cpu(cpu));
        chips
    }
}
