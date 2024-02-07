use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::air::Array;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;

use super::add_rc::AddRcOperation;
use super::constants::RC_16_30;
use super::external_linear_permute::ExternalLinearPermuteOperation;
use super::sbox::SBoxOperation;
use super::P2_WIDTH;

pub const NUM_POSEIDON2_EXTERNAL_COLS: usize = size_of::<Poseidon2ExternalCols<u8>>();

// TODO: These constants may need to live in mod.rs
// Also, which one of these should be generic?
pub const P2_DEFAULT_ROUNDS_F: usize = 8;
pub const P2_DEFAULT_ROUNDS_P: usize = 22;
pub const P2_TOTAL_ROUNDS: usize = P2_DEFAULT_ROUNDS_F + P2_DEFAULT_ROUNDS_P;

/// The number of times to loop in the first or the last external round of Poseidon2.
pub const P2_EXTERNAL_ROUND_COUNT: usize = P2_DEFAULT_ROUNDS_F / 2;
pub const P2_SBOX_EXPONENT: usize = 7;

/// The number of bits necessary to express `P2_SBOX_EXPONENT`. Used to decide how many times
/// we need to square an element to raise it to the power of `P2_SBOX_EXPONENT` using the
/// exponentiation by squaring algorithm.
pub const P2_SBOX_EXPONENT_LOG2: usize = 3;

pub const P2_ROUND_CONSTANTS: [[u32; P2_WIDTH]; P2_TOTAL_ROUNDS] = RC_16_30;

/// Cols to perform the either the first or the last external round of Poseidon2.
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
///
/// TODO: Maybe I can put these consts in one parameter struct.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalCols<T> {
    pub segment: T,
    pub clk: T,

    /// An array whose i-th element records when we read the i-th word of the state.
    /// TODO: I should be able to calculate that without using this.
    pub mem_read_clk: Array<T, P2_WIDTH>,

    /// An array whose i-th element records when we write the i-th word of the state.
    /// TODO: I should be able to calculate that without using this.
    pub mem_write_clk: Array<T, P2_WIDTH>,

    pub state_ptr: T,

    pub mem_reads: Array<MemoryReadCols<T>, P2_WIDTH>,
    pub mem_writes: Array<MemoryWriteCols<T>, P2_WIDTH>,

    pub mem_addr: Array<T, P2_WIDTH>,

    pub add_rc: AddRcOperation<T>,

    pub sbox: SBoxOperation<T>,

    pub external_linear_permute: ExternalLinearPermuteOperation<T>,

    /// The index of the current round.                                                                             
    pub round_number: T,

    /// The round constants for this round.
    pub round_constant: Array<T, P2_WIDTH>,

    /// A boolean array whose `n`th element indicates whether this is the `n`th round.                              
    pub is_round_n: Array<T, P2_EXTERNAL_ROUND_COUNT>,

    pub is_external: T,

    pub is_real: T,
}
