use p3_air::BaseAir;
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::{memory::MemoryReadWriteCols, operations::BabyBearWordRangeChecker};

use super::MemoryInstructionsChip;

pub const NUM_MEMORY_INSTRUCTIONS_COLUMNS: usize = size_of::<MemoryInstructionsColumns<u8>>();

impl<F> BaseAir<F> for MemoryInstructionsChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INSTRUCTIONS_COLUMNS
    }
}

/// The column layout for memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInstructionsColumns<T> {
    /// The program counter of the instruction.
    pub pc: T,

    /// The shard number.
    pub shard: T,
    /// The clock cycle number.
    pub clk: T,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,
    /// Whether the first operand is register zero.
    pub op_a_0: T,

    /// Whether this is a load byte instruction.
    pub is_lb: T,
    /// Whether this is a load byte unsigned instruction.
    pub is_lbu: T,
    /// Whether this is a load half instruction.
    pub is_lh: T,
    /// Whether this is a load half unsigned instruction.
    pub is_lhu: T,
    /// Whether this is a load word instruction.
    pub is_lw: T,
    /// Whether this is a store byte instruction.
    pub is_sb: T,
    /// Whether this is a store half instruction.
    pub is_sh: T,
    /// Whether this is a store word instruction.
    pub is_sw: T,

    /// The relationships among addr_word, addr_aligned, and addr_offset is as follows:
    /// addr_aligned = addr_word - addr_offset
    /// addr_offset = addr_word % 4
    /// Note that this all needs to be verified in the AIR
    pub addr_word: Word<T>,

    /// The aligned address.
    pub addr_aligned: T,
    /// The LE bit decomp of the least significant byte of address aligned.
    pub addr_aligned_least_sig_byte_decomp: [T; 6],

    /// The address offset.
    pub addr_offset: T,
    /// Whether the address offset is one.
    pub offset_is_one: T,
    /// Whether the address offset is two.
    pub offset_is_two: T,
    /// Whether the address offset is three.
    pub offset_is_three: T,

    /// Gadget to verify that the address word is within the Baby-Bear field.
    pub addr_word_range_checker: BabyBearWordRangeChecker<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryReadWriteCols<T>,

    /// Used for load memory instructions to store the unsigned memory value.
    pub unsigned_mem_val: Word<T>,

    // LE bit decomposition for the most significant byte of `unsigned_mem_val`.  This is used to
    // determine the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [T; 8],

    /// Flag for load memory instructions that contains bool value of
    /// (memory value is neg) && (op_a != registor 0).
    pub mem_value_is_neg_not_x0: T,
    /// Flag for load memory instructions that contains bool value of
    /// (memory value is pos) && (op_a != registor 0).
    pub mem_value_is_pos_not_x0: T,

    /// Nonces for the ALU operations.
    pub addr_word_nonce: T,
    pub unsigned_mem_val_nonce: T,
}
