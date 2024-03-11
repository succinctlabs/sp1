pub mod air;
pub mod columns;
pub mod event;
pub mod trace;

pub use event::*;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;
