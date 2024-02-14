use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::operations::FixedRotateRightOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

/// `S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct S0Operation<T> {
    pub a_rr_2: FixedRotateRightOperation<T>,
    pub a_rr_13: FixedRotateRightOperation<T>,
    pub a_rr_22: FixedRotateRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,
    pub s0: XorOperation<T>,
}

impl<F: Field> S0Operation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, a: u32) -> u32 {
        let a_rr_2 = self.a_rr_2.populate(record, a, 2);
        let a_rr_13 = self.a_rr_13.populate(record, a, 13);
        let a_rr_22 = self.a_rr_22.populate(record, a, 22);
        let s0_intermediate = self.s0_intermediate.populate(record, a_rr_2, a_rr_13);
        self.s0.populate(record, s0_intermediate, a_rr_22)
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: S0Operation<AB::Var>,
        is_real: AB::Var,
    ) {
        // S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22).
        FixedRotateRightOperation::<AB::F>::eval(builder, a, 2, cols.a_rr_2, is_real);
        FixedRotateRightOperation::<AB::F>::eval(builder, a, 13, cols.a_rr_13, is_real);
        FixedRotateRightOperation::<AB::F>::eval(builder, a, 22, cols.a_rr_22, is_real);
        XorOperation::<AB::F>::eval(
            builder,
            cols.a_rr_2.value,
            cols.a_rr_13.value,
            cols.s0_intermediate,
            is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            cols.s0_intermediate.value,
            cols.a_rr_22.value,
            cols.s0,
            is_real,
        );
        builder.assert_bool(is_real);
    }
}
