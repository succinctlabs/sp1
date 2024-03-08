use crate::air::CpuChip;
use p3_field::PrimeField32;
use sp1_derive::MachineAir;

#[derive(MachineAir)]
#[sp1_core_path = "sp1_core"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
pub enum RecursionAir<F: PrimeField32> {
    Cpu(CpuChip<F>),
}
