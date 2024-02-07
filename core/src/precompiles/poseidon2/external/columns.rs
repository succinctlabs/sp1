use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;

use super::add_rc::AddRcOperation;
use super::external_linear_permute::ExternalLinearPermuteOperation;
use super::sbox::SBoxOperation;
use super::P2_EXTERNAL_ROUND_COUNT;
use super::P2_WIDTH;

pub const NUM_POSEIDON2_EXTERNAL_COLS: usize = size_of::<Poseidon2ExternalCols<u8>>();

/// Cols to perform the either the first or the last external round of Poseidon2.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalCols<T> {
    pub segment: T,
    pub clk: T,

    pub state_ptr: T,

    pub mem_reads: [MemoryReadCols<T>; P2_WIDTH],
    pub mem_writes: [MemoryWriteCols<T>; P2_WIDTH],

    pub mem_addr: [T; P2_WIDTH],

    pub add_rc: AddRcOperation<T>,

    pub sbox: SBoxOperation<T>,

    pub external_linear_permute: ExternalLinearPermuteOperation<T>,

    /// The index of the current round.                                                                             
    pub round_number: T,

    /// The round constants for this round.
    pub round_constant: [T; P2_WIDTH],

    /// A boolean array whose `n`th element indicates whether this is the `n`th round.                              
    pub is_round_n: [T; P2_EXTERNAL_ROUND_COUNT],

    pub is_real: T,
}
