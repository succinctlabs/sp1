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
    pub pc: T,
    pub next_pc: T,

    pub shard: T,
    pub clk: T,

    pub opcode: T,
    pub op_a_value: Word<T>,
    pub op_b_value: Word<T>,
    pub op_c_value: Word<T>,
    pub op_a_0: T,

    pub is_load: T,
    pub is_byte: T,
    pub is_half: T,
    pub is_unsigned: T,

    pub is_lb: T,
    pub is_lh: T,

    // An addr that we are reading from or writing to as a word. We are guaranteed that this does
    // not overflow the field when reduced.

    // The relationships among addr_word, addr_aligned, and addr_offset is as follows:
    // addr_aligned = addr_word - addr_offset
    // addr_offset = addr_word % 4
    // Note that this all needs to be verified in the AIR
    pub addr_word: Word<T>,
    pub addr_word_range_checker: BabyBearWordRangeChecker<T>,

    pub addr_aligned: T,
    /// The LE bit decomp of the least significant byte of address aligned.
    pub aa_least_sig_byte_decomp: [T; 6],
    pub addr_offset: T,
    pub memory_access: MemoryReadWriteCols<T>,

    pub offset_is_one: T,
    pub offset_is_two: T,
    pub offset_is_three: T,

    pub unsigned_mem_val: Word<T>,

    // LE bit decomposition for the most significant byte of memory value.  This is used to
    // determine the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [T; 8],

    /// Flag for load mem instructions where the value is positive.
    pub mem_value_is_neg_not_x0: T,
    pub mem_value_is_pos_not_x0: T,

    pub addr_word_nonce: T,
    pub unsigned_mem_val_nonce: T,

    pub is_real: T,
}
