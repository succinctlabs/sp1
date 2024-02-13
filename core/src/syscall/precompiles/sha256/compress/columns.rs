use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::air::Word;
use crate::memory::MemoryReadWriteCols;
use crate::operations::Add5Operation;
use crate::operations::AddOperation;

use super::ch::ChOperation;
use super::maj::MajOperation;
use super::s0::S0Operation;
use super::s1::S1Operation;

pub const NUM_SHA_COMPRESS_COLS: usize = size_of::<ShaCompressCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressCols<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub w_and_h_ptr: T,

    /// The bits for cycle 8. `octet_num[9]` tells whether it is the finalize phase, and
    /// `octet_num[0]` tells whether it is the initialize phase.
    pub octet: [T; 8],

    /// This will specify which octet we are currently processing.
    /// - The first octet is for initialize.
    /// - The next 8 octets are for compress.
    /// - The last octet is for finalize.
    pub octet_num: [T; 10],

    pub mem: MemoryReadWriteCols<T>,
    pub mem_addr: T,

    pub a: Word<T>,
    pub b: Word<T>,
    pub c: Word<T>,
    pub d: Word<T>,
    pub e: Word<T>,
    pub f: Word<T>,
    pub g: Word<T>,
    pub h: Word<T>,

    /// `S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)`.
    pub s1: S1Operation<T>,

    /// `ch := (e and f) xor ((not e) and g)`.
    pub ch: ChOperation<T>,

    /// `temp1 := h + S1 + ch + k[i] + w[i]`.
    pub temp1: Add5Operation<T>,

    /// `S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)`.
    pub s0: S0Operation<T>,

    /// `maj := (a and b) xor (a and c) xor (b and c)`.
    pub maj: MajOperation<T>,

    /// `temp2 := S0 + maj`.
    pub temp2: AddOperation<T>,

    /// The next value of `e` is `d + temp1`.
    pub d_add_temp1: AddOperation<T>,

    /// The next value of `a` is `temp1 + temp2`.
    pub temp1_add_temp2: AddOperation<T>,

    pub finalize_add: AddOperation<T>,

    pub is_compression: T,

    pub is_real: T,
}
