use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::cpu::air::MemoryAccessCols;
use crate::operations::Add4Operation;
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
    i: T,

    /// The counter for initialization / finalization loops (i.e., reading / writing h0..h7).
    j: T,

    /// This flag is turned on when it's time to initialize the working variables.
    is_start: T,

    /// This flag is turned on when it's time to add the compressed chunk to the current hash value.
    is_end: T,

    rw: MemoryAccessCols<T>,

    a: Word<T>,
    b: Word<T>,
    c: Word<T>,
    d: Word<T>,
    e: Word<T>,
    f: Word<T>,
    g: Word<T>,
    h: Word<T>,

    e_rr_6: FixedRotateRightOperation<T>,
    e_rr_11: FixedRotateRightOperation<T>,
    e_rr_25: FixedRotateRightOperation<T>,
    s1_intermediate: XorOperation<T>,
    s1: XorOperation<T>,

    e_and_f: AndOperation<T>,
    e_not: NotOperation<T>,
    e_not_and_g: AndOperation<T>,
    ch: XorOperation<T>,

    temp1: Add4Operation<T>,

    a_rr_2: FixedRotateRightOperation<T>,
    a_rr_13: FixedRotateRightOperation<T>,
    a_rr_22: FixedRotateRightOperation<T>,
    s0_intermediate: XorOperation<T>,
    s0: XorOperation<T>,

    a_and_b: AndOperation<T>,
    a_and_c: AndOperation<T>,
    b_and_c: AndOperation<T>,
    maj_intermediate: XorOperation<T>,
    maj: XorOperation<T>,

    temp2: AddOperation<T>,

    d_add_temp1: AddOperation<T>,
    temp1_add_temp2: AddOperation<T>,
}
