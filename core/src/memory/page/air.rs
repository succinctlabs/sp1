use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;

use crate::air::{Bool, CurtaAirBuilder, Word};
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;

use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

pub const NUM_PAGE_COLS: usize = size_of::<PageCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct PageCols<T> {
    /// The address of the memory access.
    pub addr: Word<T>,
    /// The value being read from or written to memory.
    pub value: Word<T>,
}

// #[derive(Debug, Clone, AlignedBorrow)]
// #[repr(C)]
// pub struct InputPageCols<T> {

// }

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct OutputPageCols<T> {
    /// The clock cycle value for this memory access.
    pub clk: T,
    /// Whether the memory was being read from or written to.
    pub is_read: Bool<T>,
}
