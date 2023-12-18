use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::ByteChip;
use super::NUM_BYTE_OPS;

pub const NUM_BYTE_COLS: usize = size_of::<ByteCols<u8>>();
pub(crate) const BYTE_COL_MAP: ByteCols<usize> = make_col_map();
pub(crate) const BYTE_MULT_INDICES: [usize; NUM_BYTE_OPS] = BYTE_COL_MAP.multiplicities;

const fn make_col_map() -> ByteCols<usize> {
    let indices_arr = indices_arr::<NUM_BYTE_COLS>();
    unsafe { transmute::<[usize; NUM_BYTE_COLS], ByteCols<usize>>(indices_arr) }
}

#[derive(Debug, Clone, Copy, AlignedBorrow)]
pub struct ByteCols<T> {
    /// The first byte operand.
    pub a: T,
    /// The second byte operand.
    pub b: T,
    /// The result of the `AND` operation on `a` and `b`
    pub and: T,
    /// The result of the `OR` operation on `a` and `b`
    pub or: T,
    /// The result of the `XOR` operation on `a` and `b`
    pub xor: T,
    /// The result of the `SLL` operation on `a` and `b`
    pub sll: T,
    pub multiplicities: [T; NUM_BYTE_OPS],
}

impl<F: Field> BaseAir<F> for ByteChip<F> {
    fn width(&self) -> usize {
        NUM_BYTE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for ByteChip<AB::F> {
    fn eval(&self, builder: &mut AB) {}
}
