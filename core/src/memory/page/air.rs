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

use super::InputPage;
use super::OutputPage;

pub const NUM_PAGE_COLS: usize = size_of::<PageCols<u8>>();
pub const NUM_OUT_PAGE_COLS: usize = size_of::<OutputPageCols<u8>>();

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

impl<F: Field> BaseAir<F> for InputPage {
    fn width(&self) -> usize {
        NUM_PAGE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for InputPage {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PageCols<AB::Var> = main.row_slice(0).borrow();

        builder.send_memory(
            AB::F::zero(),
            local.addr,
            local.value,
            AB::F::zero(),
            AB::F::one(),
        )
    }
}

impl<F: Field> BaseAir<F> for OutputPage {
    fn width(&self) -> usize {
        NUM_PAGE_COLS + NUM_OUT_PAGE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for OutputPage {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PageCols<AB::Var> = main.row_slice(0).borrow();
        let out: &OutputPageCols<AB::Var> = main.row_slice(NUM_PAGE_COLS).borrow();

        builder.send_memory(
            out.clk,
            local.addr,
            local.value,
            out.is_read.0,
            AB::F::one(),
        )
    }
}
