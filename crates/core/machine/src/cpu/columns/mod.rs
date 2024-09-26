mod auipc;
mod branch;
mod ecall;
mod instruction;
mod jump;
mod memory;
mod opcode;
mod opcode_specific;

pub use auipc::*;
pub use branch::*;
pub use ecall::*;
pub use instruction::*;
pub use jump::*;
pub use memory::*;
pub use opcode::*;
pub use opcode_specific::*;

use p3_util::indices_arr;
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::{size_of, transmute};

use crate::memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current shard.
    pub shard: T,

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

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    pub opcode_specific_columns: OpcodeSpecificCols<T>,

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

    /// Flag for load mem instructions where the value is negative and not writing to x0.
    /// More formally, it is
    ///
    /// > (is_lb | is_lh) & (most_sig_byte_decomp[7] == 1) & (not writing to x0)
    pub mem_value_is_neg_not_x0: T,

    /// Flag for load mem instructions where the value is positive and not writing to x0.
    /// More formally, it is
    ///
    /// (
    ///     ((is_lb | is_lh) & (most_sig_byte_decomp[7] == 0)) |
    ///     is_lbu | is_lhu | is_lw
    /// ) &
    /// (not writing to x0)
    pub mem_value_is_pos_not_x0: T,

    /// The unsigned memory value is the value after the offset logic is applied. Used for the load
    /// memory opcodes (i.e. LB, LH, LW, LBU, and LHU).
    pub unsigned_mem_val: Word<T>,

    pub unsigned_mem_val_nonce: T,

    /// The result of selectors.is_ecall * the send_to_table column for the ECALL opcode.
    pub ecall_mul_send_to_table: T,

    /// The result of selectors.is_ecall * (is_halt || is_commit_deferred_proofs)
    pub ecall_range_check_operand: T,

    /// This is true for all instructions that are not jumps, branches, and halt.  Those
    /// instructions may move the program counter to a non sequential instruction.
    pub is_sequential_instr: T,
}

impl<T: Copy> CpuCols<T> {
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
