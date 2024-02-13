use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::operations::FixedRotateRightOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct S1Operation<T> {
    pub e_rr_6: FixedRotateRightOperation<T>,
    pub e_rr_11: FixedRotateRightOperation<T>,
    pub e_rr_25: FixedRotateRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,
    pub s1: XorOperation<T>,
}

impl<F: Field> S1Operation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, e: u32) -> u32 {
        let e_rr_6 = self.e_rr_6.populate(record, e, 6);
        let e_rr_11 = self.e_rr_11.populate(record, e, 11);
        let e_rr_25 = self.e_rr_25.populate(record, e, 25);
        let s1_intermediate = self.s1_intermediate.populate(record, e_rr_6, e_rr_11);

        self.s1.populate(record, s1_intermediate, e_rr_25)
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        e: Word<AB::Var>,
        cols: S1Operation<AB::Var>,
        is_real: AB::Var,
    ) {
        FixedRotateRightOperation::<AB::F>::eval(builder, e, 6, cols.e_rr_6, is_real);
        FixedRotateRightOperation::<AB::F>::eval(builder, e, 11, cols.e_rr_11, is_real);
        FixedRotateRightOperation::<AB::F>::eval(builder, e, 25, cols.e_rr_25, is_real);
        XorOperation::<AB::F>::eval(
            builder,
            cols.e_rr_6.value,
            cols.e_rr_11.value,
            cols.s1_intermediate,
            is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            cols.s1_intermediate.value,
            cols.e_rr_25.value,
            cols.s1,
            is_real,
        );
        builder.assert_bool(is_real);
    }
}
