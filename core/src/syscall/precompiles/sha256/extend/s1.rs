use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::memory::MemoryReadCols;
use crate::operations::FixedRotateRightOperation;
use crate::operations::FixedShiftRightOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

/// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct S1Operation<T> {
    pub w_i_minus_2: MemoryReadCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,
    pub s1: XorOperation<T>,
}

impl<F: Field> S1Operation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, w_i_minus_2: u32) -> u32 {
        let w_i_minus_2_rr_17 = self.w_i_minus_2_rr_17.populate(record, w_i_minus_2, 17);
        let w_i_minus_2_rr_19 = self.w_i_minus_2_rr_19.populate(record, w_i_minus_2, 19);
        let w_i_minus_2_rs_10 = self.w_i_minus_2_rs_10.populate(record, w_i_minus_2, 10);
        let s1_intermediate =
            self.s1_intermediate
                .populate(record, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
        self.s1.populate(record, s1_intermediate, w_i_minus_2_rs_10)
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        w_i_minus_2: Word<AB::Var>,
        cols: S1Operation<AB::Var>,
        is_real: AB::Var,
    ) {
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            17,
            cols.w_i_minus_2_rr_17,
            is_real,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            19,
            cols.w_i_minus_2_rr_19,
            is_real,
        );
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            10,
            cols.w_i_minus_2_rs_10,
            is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            cols.w_i_minus_2_rr_17.value,
            cols.w_i_minus_2_rr_19.value,
            cols.s1_intermediate,
            is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            cols.s1_intermediate.value,
            cols.w_i_minus_2_rs_10.value,
            cols.s1,
            is_real,
        );
    }
}
