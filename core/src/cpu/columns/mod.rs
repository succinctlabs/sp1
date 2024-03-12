mod auipc;
mod branch;
mod instruction;
mod jump;
mod memory;
mod opcode;

pub use auipc::*;
pub use branch::*;
pub use instruction::*;
pub use jump::*;
pub use memory::*;
pub use opcode::*;

use core::borrow::{Borrow, BorrowMut};
use p3_util::indices_arr;
use sp1_derive::AlignedBorrow;
use std::mem::{size_of, transmute};

use crate::{
    air::Word,
    memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols},
    operations::IsEqualWordOperation,
};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

pub const OPCODE_SPECIFIC_COLUMNS_SIZE: usize = size_of_opcode_specific_columns();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T> {
    /// The current shard.
    pub shard: T,

    /// The clock cycle value.
    pub clk: T,

    /// The program counter value.
    pub pc: T,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    /// This is transmuted to MemoryColumns, BranchColumns, JumpColumns, or AUIPCColumns
    pub opcode_specific_columns: [T; OPCODE_SPECIFIC_COLUMNS_SIZE],

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,

    /// The branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & (a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & a_lt_b ||
    /// > (is_bge | is_bgeu) & (a_eq_b | a_gt_b)
    pub branching: T,

    /// The not branching column is equal to:
    ///
    /// > is_beq & !a_eq_b ||
    /// > is_bne & !(a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & !a_lt_b ||
    /// > (is_bge | is_bgeu) & !(a_eq_b | a_gt_b)
    pub not_branching: T,

    /// The memory value is negative column is equal to:
    ///
    /// > (is_lbu | is_lhu) & (most_sig_byte_decomp[7] == 1)
    pub mem_value_is_neg: T,

    /// The unsigned memory value is the value after the offset logic is applied. Used for the load
    /// memory opcodes (i.e. LB, LH, LW, LBU, and LHU).
    pub unsigned_mem_val: Word<T>,

    /// The result of send_to_table * ecall
    pub ecall_mul_send_to_table: T,
}

impl<T: Clone> CpuCols<T> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        self.op_a_access.value().clone()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        self.op_b_access.value().clone()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        self.op_c_access.value().clone()
    }
}

/// Creates the column map for the CPU.
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

/// Returns the size of the opcode specific columns and makes sure each opcode specific column fits.
const fn size_of_opcode_specific_columns() -> usize {
    let memory_columns_size = NUM_MEMORY_COLUMNS;
    let branch_columns_size = NUM_BRANCH_COLS;
    let jump_columns_size = NUM_JUMP_COLS;
    let aui_pc_columns_size = NUM_AUIPC_COLS;

    if branch_columns_size > memory_columns_size {
        panic!("BranchColumns is too large to fit in the opcode_specific_columns array.");
    } else if jump_columns_size > memory_columns_size {
        panic!("JumpColumns is too large to fit in the opcode_specific_columns array.");
    } else if aui_pc_columns_size > memory_columns_size {
        panic!("AUIPCColumns is too large to fit in the opcode_specific_columns array.");
    }

    memory_columns_size
}
