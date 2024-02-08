pub mod air;
pub mod columns;
pub mod event;
pub mod memory;
pub mod trace;

pub use event::*;
pub use memory::*;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;
