use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::air::Word;
use crate::memory::MemoryReadWriteCols;
use crate::operations::Add5Operation;
use crate::operations::AddOperation;
use crate::operations::AndOperation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::NotOperation;
use crate::operations::XorOperation;

pub const NUM_SHA512_COMPRESS_COLS: usize = size_of::<Sha512CompressCols<u8>>();

/// A set of columns needed to compute the SHA-256 compression function.
///
/// Each sha compress syscall is processed over 80 columns, split into 10 octets. The first octet is
/// for initialization, the next 8 octets are for compression, and the last octet is for finalize.
/// During init, the columns are initialized with the input values, one word at a time. During each
/// compression cycle, one iteration of sha compress is computed. During finalize, the columns are
/// combined and written back to memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Sha512CompressCols<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub w_ptr: T,
    pub h_ptr: T,

    pub start: T,

    /// Which cycle within the octet we are currently processing.
    pub octet: [T; 8],

    /// This will specify which octet we are currently processing.
    ///  - The first octet is for initialize.
    ///  - The next 16 octets are for compress.
    ///  - The last octet is for finalize.
    pub octet_num: [T; 18],

    /// Memory access. During init and compression, this is read only. During finalize, this is
    /// used to write the result into memory.
    pub mem: MemoryReadWriteCols<T>,
    /// Current memory address being written/read. During init and finalize, this is A-H. During
    /// compression, this is w[i] being read only.
    pub mem_addr: T,

    pub a: Word<T>,
    pub b: Word<T>,
    pub c: Word<T>,
    pub d: Word<T>,
    pub e: Word<T>,
    pub f: Word<T>,
    pub g: Word<T>,
    pub h: Word<T>,

    /// Current value of K[i]. This is a constant array that loops around every 80 iterations.
    pub k: Word<T>,

    pub e_rr_14: FixedRotateRightOperation<T>,
    pub e_rr_18: FixedRotateRightOperation<T>,
    pub e_rr_41: FixedRotateRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,
    /// `S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)`.
    pub s1: XorOperation<T>,

    pub e_and_f: AndOperation<T>,
    pub e_not: NotOperation<T>,
    pub e_not_and_g: AndOperation<T>,
    /// `ch := (e and f) xor ((not e) and g)`.
    pub ch: XorOperation<T>,

    /// `temp1 := h + S1 + ch + k[i] + w[i]`.
    pub temp1: Add5Operation<T>,

    pub a_rr_28: FixedRotateRightOperation<T>,
    pub a_rr_34: FixedRotateRightOperation<T>,
    pub a_rr_39: FixedRotateRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,
    /// `S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)`.
    pub s0: XorOperation<T>,

    pub a_and_b: AndOperation<T>,
    pub a_and_c: AndOperation<T>,
    pub b_and_c: AndOperation<T>,
    pub maj_intermediate: XorOperation<T>,
    /// `maj := (a and b) xor (a and c) xor (b and c)`.
    pub maj: XorOperation<T>,

    /// `temp2 := S0 + maj`.
    pub temp2: AddOperation<T>,

    /// The next value of `e` is `d + temp1`.
    pub d_add_temp1: AddOperation<T>,
    /// The next value of `a` is `temp1 + temp2`.
    pub temp1_add_temp2: AddOperation<T>,

    /// During finalize, this is one of a-h and is being written into `mem`.
    pub finalized_operand: Word<T>,
    pub finalize_add: AddOperation<T>,

    pub is_compression: T,
    pub is_last_row: T,

    pub is_real: T,
}
