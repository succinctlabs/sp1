use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::operations::Add5Operation;
use crate::operations::AddOperation;
use crate::operations::AndOperation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::NotOperation;
use crate::operations::XorOperation;

pub const NUM_SHA_COMPRESS_COLS: usize = size_of::<ShaCompressCols<u8>>();

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct ShaCompressCols<T> {
    /// Inputs.
    pub segment: T,
    pub clk: T,
    pub w_and_h_ptr: T,

    /// The counter for the main loop.
    pub i: T,

    /// The counter for initialization / finalization loops (i.e., reading / writing h0..h7).
    pub octet: [T; 8],

    // This will specify which octet we are currently processing.
    // The first octect is for initialize.
    // The next 8 octects are for compress.
    // The last octect is for finalize.
    pub octet_num: [T; 10],

    pub mem: MemoryAccessCols<T>,
    pub mem_addr: T,

    pub a: Word<T>,
    pub b: Word<T>,
    pub c: Word<T>,
    pub d: Word<T>,
    pub e: Word<T>,
    pub f: Word<T>,
    pub g: Word<T>,
    pub h: Word<T>,

    pub e_rr_6: FixedRotateRightOperation<T>,
    pub e_rr_11: FixedRotateRightOperation<T>,
    pub e_rr_25: FixedRotateRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,
    pub s1: XorOperation<T>,

    pub e_and_f: AndOperation<T>,
    pub e_not: NotOperation<T>,
    pub e_not_and_g: AndOperation<T>,
    pub ch: XorOperation<T>,

    pub temp1: Add5Operation<T>,

    pub a_rr_2: FixedRotateRightOperation<T>,
    pub a_rr_13: FixedRotateRightOperation<T>,
    pub a_rr_22: FixedRotateRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,
    pub s0: XorOperation<T>,

    pub a_and_b: AndOperation<T>,
    pub a_and_c: AndOperation<T>,
    pub b_and_c: AndOperation<T>,
    pub maj_intermediate: XorOperation<T>,
    pub maj: XorOperation<T>,

    pub temp2: AddOperation<T>,

    pub d_add_temp1: AddOperation<T>,
    pub temp1_add_temp2: AddOperation<T>,

    pub finalize_add: AddOperation<T>,

    pub is_initialize: T,
    pub is_compression: T,
    pub is_finalize: T,

    pub is_real: T,
}
