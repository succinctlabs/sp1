use std::mem::size_of;

use opcode_specific::OpcodeSpecificCols;
use sp1_derive::AlignedBorrow;

use crate::air::Word;
use crate::cpu::main::columns::OpcodeSelectorCols;

mod auipc;
mod branch;
mod ecall;
mod jump;
pub mod memory;
mod opcode_specific;

pub const NUM_CPU_AUX_COLS: usize = size_of::<CpuAuxCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuAuxCols<T: Copy> {
    /// The current shard.
    pub shard: T,
    /// The current clk.
    pub clk: T,
    /// The channel value, used for byte lookup multiplicity.
    pub channel: T,

    /// The program counter value.
    pub pc: T,

    /// The expected next program counter value.
    pub next_pc: T,

    pub op_a_prev_val: Word<T>,
    pub op_a_val: Word<T>,
    pub op_b_val: Word<T>,
    pub op_c_val: Word<T>,
    pub op_a_0: T,

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

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

    /// The memory value is negative column is equal to:
    ///
    /// > (is_lbu | is_lhu) & (most_sig_byte_decomp[7] == 1)
    pub mem_value_is_neg: T,

    /// The unsigned memory value is the value after the offset logic is applied. Used for the load
    /// memory opcodes (i.e. LB, LH, LW, LBU, and LHU).
    pub unsigned_mem_val: Word<T>,

    pub unsigned_mem_val_nonce: T,

    /// The result of selectors.is_ecall * the send_to_table column for the ECALL opcode.
    pub ecall_mul_send_to_table: T,

    /// The result of selectors.is_ecall * (is_halt || is_commit_deferred_proofs)
    pub ecall_range_check_operand: T,

    pub is_halt: T,
}
