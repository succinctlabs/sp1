use core::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, transmute};

use p3_field::PrimeField32;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::air::Word;

use super::{instruction_cols::InstructionCols, opcode_cols::OpcodeSelectors};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T> {
    pub value: Word<T>,
    pub prev_value: Word<T>,

    // The previous segment and timestamp that this memory access is being read from.
    pub prev_segment: T,
    pub prev_clk: T,

    // The three columns below are helper/materialized columns used to verify that this memory access is
    // after the last one.  Specifically, it verifies that the current clk value > timestsamp (if
    // this access's segment == prev_access's segment) or that the current segment > segment.
    // These columns will need to be verified in the air.

    // This will be true if the current segment == prev_access's segment, else false.
    pub use_clk_comparison: T,

    // This materialized column is equal to use_clk_comparison ? prev_timestamp : current_segment
    pub prev_time_value: T,
    // This materialized column is equal to use_clk_comparison ? current_clk : current_segment
    pub current_time_value: T,
}
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
    pub memory_access: MemoryAccessCols<T>,

    pub offset_is_one: T,
    pub offset_is_two: T,
    pub offset_is_three: T,

    // LE bit decomposition for the most significant byte of memory value.  This is used to determine
    // the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [T; 8],
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchColumns<T> {
    pub pc: Word<T>,
    pub next_pc: Word<T>,

    pub a_eq_b: T,
    pub a_gt_b: T,
    pub a_lt_b: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpColumns<T> {
    pub pc: Word<T>, // These are needed for JAL
    pub next_pc: Word<T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCColumns<T> {
    pub pc: Word<T>,
}

/// An AIR table for memory accesses.
#[derive(AlignedBorrow, Default, Debug)]
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
    pub selectors: OpcodeSelectors<T>,

    // Operand values, either from registers or immediate values.
    pub op_a_access: MemoryAccessCols<T>,
    pub op_b_access: MemoryAccessCols<T>,
    pub op_c_access: MemoryAccessCols<T>,

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
    let branch_columns_size = size_of::<BranchColumns<u8>>();
    let jump_columns_size = size_of::<JumpColumns<u8>>();
    let aui_pc_columns_size = size_of::<AUIPCColumns<u8>>();

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

impl CpuCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_CPU_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        unsafe { transmute::<[u32; NUM_CPU_COLS], CpuCols<u32>>(sized) }
    }
}

impl<T> CpuCols<T> {
    pub fn op_a_val(&self) -> &Word<T> {
        &self.op_a_access.value
    }

    pub fn op_b_val(&self) -> &Word<T> {
        &self.op_b_access.value
    }

    pub fn op_c_val(&self) -> &Word<T> {
        &self.op_c_access.value
    }
}
