use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::operations::IsZeroOperation;

pub const NUM_ECALL_COLS: usize = size_of::<EcallCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct EcallCols<T> {
    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current ecall is LWA.
    pub is_lwa: IsZeroOperation<T>,

    /// Whether the current ecall is HALT.
    pub is_halt: IsZeroOperation<T>,
}
