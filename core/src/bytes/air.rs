use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::ByteChip;

pub const NUM_BYTE_COLS: usize = size_of::<ByteCols<u8>>();

#[derive(Debug, Clone, Copy, AlignedBorrow)]
pub struct ByteCols<T> {
    pub opcode: T,
    pub a: T,
    pub b: T,
    pub c: T,
    pub multiplicity: T,
}

const fn make_col_map() -> ByteCols<usize> {
    let indices_arr = indices_arr::<NUM_BYTE_COLS>();
    unsafe { transmute::<[usize; NUM_BYTE_COLS], ByteCols<usize>>(indices_arr) }
}

impl<F: Field> BaseAir<F> for ByteChip {
    fn width(&self) -> usize {
        NUM_BYTE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for ByteChip {
    fn eval(&self, builder: &mut AB) {}
}
