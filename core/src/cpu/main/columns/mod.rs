pub mod channel;
pub mod instruction;
pub mod opcode;

pub use channel::*;
pub use instruction::*;
pub use opcode::*;

use p3_util::indices_arr;
use sp1_derive::AlignedBorrow;
use std::mem::{size_of, transmute};

use crate::{
    air::Word,
    memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols},
};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current shard.
    pub shard: T,
    /// The channel value, used for byte lookup multiplicity.
    pub channel: T,

    pub nonce: T,

    /// The clock cycle value.  This should be within 24 bits.
    pub clk: T,
    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The program counter value.
    pub pc: T,

    /// The expected next program counter value.
    pub next_pc: T,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Columns related to the byte lookup channel.
    pub channel_selectors: ChannelSelectorCols<T>,

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    pub is_halt: T,

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,
}

impl<T: Copy> CpuCols<T> {
    /// Gets the prev value of the first operand.
    pub fn op_a_prev_val(&self) -> Word<T> {
        *self.op_a_access.prev_value()
    }

    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        *self.op_a_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}

/// Creates the column map for the CPU.
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}
