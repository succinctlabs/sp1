use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::{
    memory::MemoryReadWriteCols,
    operations::{BabyBearWordRangeChecker, IsZeroOperation},
};

pub const NUM_MEMORY_INSTRUCTIONS_COLUMNS: usize = size_of::<MemoryInstructionsColumns<u8>>();

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
    /// The address's least significant two bits.
    pub addr_ls_two_bits: T,

    /// Whether the least significant two bits of the address are one.
    pub ls_bits_is_one: T,
    /// Whether the least significant two bits of the address are two.
    pub ls_bits_is_two: T,
    /// Whether the least significant two bits of the address are three.
    pub ls_bits_is_three: T,

    /// Gadget to verify that the address word is within the Baby-Bear field.
    pub addr_word_range_checker: BabyBearWordRangeChecker<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryReadWriteCols<T>,

    /// Used for load memory instructions to store the unsigned memory value.
    pub unsigned_mem_val: Word<T>,

    /// The most significant bit of `unsigned_mem_val`.  This is relevant for LB and LH instructions.
    pub most_sig_bit: T,

    /// The most significant byte of `unsigned_mem_val`.  This is relevant for LB and LH instructions.
    /// For LB this is equal to unsigned_mem_val\[0\] and for LH this is equal to unsigned_mem_val\[1\].
    pub most_sig_byte: T,

    /// Flag for load memory instructions that contains bool value of
    /// (memory value is neg) && (op_a != registor 0).
    pub mem_value_is_neg_not_x0: T,
    /// Flag for load memory instructions that contains bool value of
    /// (memory value is pos) && (op_a != registor 0).
    pub mem_value_is_pos_not_x0: T,

    /// This is used to check if the most significant three bytes of the memory address are all zero.
    pub most_sig_bytes_zero: IsZeroOperation<T>,
}
