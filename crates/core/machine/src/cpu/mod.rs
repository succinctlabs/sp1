use sp1_core_executor::RiscvAirId;

pub mod air;
pub mod columns;
pub mod trace;

/// The maximum log degree of the CPU chip to avoid lookup multiplicity overflow.
pub const MAX_CPU_LOG_DEGREE: usize = 22;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;

impl CpuChip {
    pub fn id(&self) -> RiscvAirId {
        RiscvAirId::Cpu
    }
}
