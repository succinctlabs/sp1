use std::mem::size_of;

use crate::memory::{MemoryReadCols, MemoryReadWriteCols};
use p3_air::BaseAir;
use sp1_derive::AlignedBorrow;

mod branch;
mod heap_expand;
mod instruction;
mod memory;
mod opcode;
mod opcode_specific;
mod public_values;

pub use instruction::*;
pub use opcode::*;
pub use public_values::*;

use self::opcode_specific::OpcodeSpecificCols;

use super::CpuChip;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

impl<F: Send + Sync, const L: usize> BaseAir<F> for CpuChip<F, L> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Debug)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,

    pub a: MemoryReadWriteCols<T>,
    pub b: MemoryReadCols<T>,
    pub c: MemoryReadCols<T>,

    pub opcode_specific: OpcodeSpecificCols<T>,

    pub is_real: T,
}
