use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::{air::Word, memory::MemoryReadWriteCols, operations::BabyBearWordRangeChecker};

pub const NUM_MEMORY_COLUMNS: usize = size_of::<MemoryColumns<u8>>();

/// The column layout for memory.
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
    pub addr_word_range_checker: BabyBearWordRangeChecker<T>,

    pub addr_aligned: T,
    /// The LE bit decomp of the least significant byte of address aligned.
    pub aa_least_sig_byte_decomp: [T; 6],
    pub addr_offset: T,
    pub memory_access: MemoryReadWriteCols<T>,

    pub offset_is_one: T,
    pub offset_is_two: T,
    pub offset_is_three: T,

    // LE bit decomposition for the most significant byte of memory value.  This is used to determine
    // the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [T; 8],

    pub addr_word_nonce: T,
    pub unsigned_mem_val_nonce: T,
}
