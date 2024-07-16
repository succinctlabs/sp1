pub mod aux;
pub mod event;
pub mod main;

pub use event::*;

/// The maximum log degree of the CPU chip to avoid lookup multiplicity overflow.
pub const MAX_CPU_LOG_DEGREE: usize = 22;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;

/// A chip that implements non ALU opcodes.
#[derive(Default)]
pub struct CpuAuxChip;
