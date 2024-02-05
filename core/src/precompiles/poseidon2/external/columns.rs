use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::air::Array;
use crate::air::Word;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::AddOperation;
use crate::utils::ec::NUM_WORDS_FIELD_ELEMENT;

use super::add_rc::AddRcOperation;

pub const NUM_POSEIDON2_EXTERNAL_COLS: usize = size_of::<Poseidon2ExternalCols<u8>>();

// TODO: These constants may need to live in mod.rs
// Also, which one of these should be generic?
pub const POSEIDON2_DEFAULT_ROUNDS_F: usize = 8;
pub const POSEIDON2_DEFAULT_ROUNDS_P: usize = 22;
pub const POSEIDON2_DEFAULT_TOTAL_ROUNDS: usize =
    POSEIDON2_DEFAULT_ROUNDS_F + POSEIDON2_DEFAULT_ROUNDS_P;
pub const POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS: usize = POSEIDON2_DEFAULT_ROUNDS_F / 2;

// TODO: Obviously this can't be a 0 array but I don't know what it should be.
pub const POSEIDON2_ROUND_CONSTANTS: [[u32; NUM_WORDS_FIELD_ELEMENT];
    POSEIDON2_DEFAULT_TOTAL_ROUNDS] =
    [[0; NUM_WORDS_FIELD_ELEMENT]; POSEIDON2_DEFAULT_TOTAL_ROUNDS];

/// Cols to perform the first external round of Poseidon2.
///
/// It's necessary to split the struct into two parts because of the const generic parameter.
/// AlignedBorrow doesn't like a struct with more than one const generic parameter.
///
/// TODO: Do I really want to make this a const generic? I feel that it'll be the same everywhere.
/// Especially, I think I was concerned about the first external round and the last external round
/// having different constants, but they should have the same NUM_WORDS_STATE.
///
/// TODO: also, i think I need to start specifying what is for the first external round only and
/// what is shared between the first and last external rounds.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalCols<T>(
    pub Poseidon2ExternalColsConfigurable<T, NUM_WORDS_FIELD_ELEMENT>,
);

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalColsConfigurable<T, const NUM_WORDS_STATE: usize> {
    pub segment: T,
    pub clk: T,

    /// An array whose i-th element records when we read the i-th word of the state.
    /// TODO: I should be able to calculate that without using this.
    pub mem_read_clk: Array<T, NUM_WORDS_STATE>,

    /// An array whose i-th element records when we write the i-th word of the state.
    /// TODO: I should be able to calculate that without using this.
    pub mem_write_clk: Array<T, NUM_WORDS_STATE>,

    pub state_ptr: T,

    pub mem_reads: Array<MemoryReadCols<T>, NUM_WORDS_STATE>,
    pub mem_writes: Array<MemoryWriteCols<T>, NUM_WORDS_STATE>,

    pub mem_addr: Array<T, NUM_WORDS_STATE>,

    pub add_rc: AddRcOperation<T>,

    /// The index of the current round.                                                                             
    pub round_number: T,

    /// The index of the current round.                                                                             
    pub round_constant: Array<Word<T>, NUM_WORDS_STATE>,

    /// A boolean array whose `n`th element indicates whether this is the `n`th round.                              
    pub is_round_n: Array<T, POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS>,

    pub is_external: T,

    pub is_real: T,
}
