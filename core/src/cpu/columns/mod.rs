pub mod instruction;
pub mod opcode;

pub use instruction::*;
pub use opcode::*;

use core::borrow::{Borrow, BorrowMut};
use p3_field::PrimeField32;
use p3_util::indices_arr;
use std::mem::{size_of, transmute};
use valida_derive::AlignedBorrow;

use crate::{
    air::Word,
    memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols},
};

pub(crate) const NUM_MEMORY_COLUMNS: usize = size_of::<MemoryColumns<u8>>();
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryColumns<T> {
    // An addr that we are reading from or writing to as a word. We are guaranteed that this does
    // not overflow the field when reduced.

    // The relationships among addr_word, addr_aligned, and addr_offset is as follows:
    // addr_aligned = addr_word - addr_offset
    // addr_offset = addr_word % 4
    // Note that this all needs to be verified in the AIR
    pub addr_word: Word<T>,
    pub addr_aligned: T,
    pub addr_offset: T,
    pub memory_access: MemoryReadWriteCols<T>,

    pub offset_is_one: T,
    pub offset_is_two: T,
    pub offset_is_three: T,

    // LE bit decomposition for the most significant byte of memory value.  This is used to determine
    // the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [T; 8],
}

pub(crate) const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    pub pc: Word<T>,
    pub next_pc: Word<T>,

    pub a_eq_b: T,
    pub a_gt_b: T,
    pub a_lt_b: T,
}

pub(crate) const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpCols<T> {
    pub pc: Word<T>, // These are needed for JAL
    pub next_pc: Word<T>,
}

pub(crate) const NUM_AUIPC_COLS: usize = size_of::<AUIPCCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCCols<T> {
    pub pc: Word<T>,
}

pub(crate) const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

pub(crate) const OPCODE_SPECIFIC_COLUMNS_SIZE: usize = get_opcode_specific_columns_offset();
// This is a constant function, so we can't have it dynamically return the largest opcode specific
// struct size.
const fn get_opcode_specific_columns_offset() -> usize {
    let memory_columns_size = size_of::<MemoryColumns<u8>>();
    let branch_columns_size = NUM_BRANCH_COLS;
    let jump_columns_size = NUM_JUMP_COLS;
    let aui_pc_columns_size = NUM_AUIPC_COLS;

    let return_val = memory_columns_size;

    if branch_columns_size > return_val {
        panic!("BranchColumns is too large to fit in the opcode_specific_columns array.");
    }

    if jump_columns_size > return_val {
        panic!("JumpColumns is too large to fit in the opcode_specific_columns array.");
    }

    if aui_pc_columns_size > return_val {
        panic!("AUIPCColumns is too large to fit in the opcode_specific_columns array.");
    }

    return_val
}

/// An AIR table for memory accesses.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T> {
    /// The current segment.
    pub segment: T,
    /// The clock cycle value.
    pub clk: T,
    // /// The program counter value.
    pub pc: T,

    // Columns related to the instruction.
    pub instruction: InstructionCols<T>,
    // Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    // Operand values, either from registers or immediate values.
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    // This is transmuted to MemoryColumns, BranchColumns, JumpColumns, or AUIPCColumns
    pub opcode_specific_columns: [T; OPCODE_SPECIFIC_COLUMNS_SIZE],

    // Selector to label whether this row is a non padded row.
    pub is_real: T,

    // Materialized columns.

    // There are columns that are combinations of other columns.
    // The reason for these columns is to keep the constraints that use them to have degree <= 3.
    // E.g. Expressions used with interactions need to be degree 1, since the interaction constraint
    // itself is degree 2.
    // Note that the value of these columns will need to be verified.

    // branching column is equal to
    // (Self::selectors::is_beq AND Self::BranchColumns::a_eq_b) ||
    // (Self::selectors::is_bne AND (Self::BranchColumns::a_lt_b || Self::BranchColumns::a_gt:b) ||
    // ((Self::selectors::is_blt || Self::selectors::is_bltu) AND Self::BranchColumns::a_lt_b) ||
    // ((Self::selectors::is_bge || Self::selectors::is_bgeu)
    //  AND (Self::BranchColumns::a_eq_b || Self::BranchColumns::a_gt_b))
    pub branching: T,

    // not_branching column is equal to
    // (Self::selectors::is_beq AND !Self::BranchColumns::a_eq_b) ||
    // (Self::selectors::is_bne AND !(Self::BranchColumns::a_lt_b || Self::BranchColumns::a_gt:b) ||
    // ((Self::selectors::is_blt || Self::selectors::is_bltu) AND !Self::BranchColumns::a_lt_b) ||
    // ((Self::selectors::is_bge || Self::selectors::is_bgeu)
    //  AND !(Self::BranchColumns::a_eq_b || Self::BranchColumns::a_gt_b))
    pub not_branching: T,

    // mem_value_is_neg column is equal to
    // ((Self::selectors::is_lbu || Self::selectors::is_lhu) AND Self::MemoryColumns::most_sig_byte_decomp[7] == 1)
    pub mem_value_is_neg: T,

    // unsigned_mem_val is the memory value after the offset logic is applied.  This is used for
    // load memory opcodes (LB, LH, LW, LBU, LHU).
    pub unsigned_mem_val: Word<T>,
}

impl CpuCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_CPU_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        *sized.as_slice().borrow()
    }
}

impl<T: Clone> CpuCols<T> {
    pub fn op_a_val(&self) -> Word<T> {
        self.op_a_access.value().clone()
    }

    pub fn op_b_val(&self) -> Word<T> {
        self.op_b_access.value().clone()
    }

    pub fn op_c_val(&self) -> Word<T> {
        self.op_c_access.value().clone()
    }
}
