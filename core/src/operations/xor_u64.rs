use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::{SP1AirBuilder, WordU64};
use crate::runtime::ExecutionRecord;

use super::XorOperation;

/// A set of columns needed to compute the xor of two `u64` words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperationU64<T> {
    /// The result of u64 `x ^ y` in two 32 bits limbs.
    pub value_hi: XorOperation<T>,
    pub value_lo: XorOperation<T>,
}

impl<F: Field> XorOperationU64<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, x: u64, y: u64) -> u64 {
        let expected = x ^ y;

        // Split the u64 into two u32 limbs.
        let (x_hi, x_lo) = ((x >> 32) as u32, x as u32);
        let (y_hi, y_lo) = ((y >> 32) as u32, y as u32);

        // Populate the two 32 bits word limbs.
        self.value_hi.populate(record, x_hi, y_hi);
        self.value_lo.populate(record, x_lo, y_lo);

        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: WordU64<AB::Var>,
        b: WordU64<AB::Var>,
        cols: XorOperationU64<AB::Var>,
        is_real: AB::Var,
    ) {
        // Split the u64 word into two u32 words.
        let (a_lo, a_hi) = a.split_into_u32_chunks();
        let (b_lo, b_hi) = b.split_into_u32_chunks();

        // apply the xor operation to the two u32 words.
        XorOperation::<AB::F>::eval(builder, a_hi, b_hi, cols.value_hi, is_real);
        XorOperation::<AB::F>::eval(builder, a_lo, b_lo, cols.value_lo, is_real);
    }
}
