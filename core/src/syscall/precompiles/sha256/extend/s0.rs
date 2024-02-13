use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::memory::MemoryReadCols;
use crate::operations::FixedRotateRightOperation;
use crate::operations::FixedShiftRightOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

/// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct S0Operation<T> {
    pub w_i_minus_15: MemoryReadCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,
    pub s0: XorOperation<T>,
}

impl<F: Field> S0Operation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, w_i_minus_15: u32) -> u32 {
        let w_i_minus_15_rr_7 = self.w_i_minus_15_rr_7.populate(record, w_i_minus_15, 7);
        let w_i_minus_15_rr_18 = self.w_i_minus_15_rr_18.populate(record, w_i_minus_15, 18);
        let w_i_minus_15_rs_3 = self.w_i_minus_15_rs_3.populate(record, w_i_minus_15, 3);
        let s0_intermediate =
            self.s0_intermediate
                .populate(record, w_i_minus_15_rr_7, w_i_minus_15_rr_18);
        self.s0.populate(record, s0_intermediate, w_i_minus_15_rs_3)
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        w_i_minus_15: Word<AB::Var>,
        cols: S0Operation<AB::Var>,
        is_real: AB::Var,
    ) {
        // s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3).

        let w_i_minus_15_rr_7 = {
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                w_i_minus_15,
                7,
                cols.w_i_minus_15_rr_7,
                is_real,
            );
            cols.w_i_minus_15_rr_7.value
        };

        let w_i_minus_15_rr_18 = {
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                w_i_minus_15,
                18,
                cols.w_i_minus_15_rr_18,
                is_real,
            );
            cols.w_i_minus_15_rr_18.value
        };

        let w_i_minus_15_rs_3 = {
            FixedShiftRightOperation::<AB::F>::eval(
                builder,
                w_i_minus_15,
                3,
                cols.w_i_minus_15_rs_3,
                is_real,
            );
            cols.w_i_minus_15_rr_18.value
        };

        let s0_intermediate = {
            XorOperation::<AB::F>::eval(
                builder,
                w_i_minus_15_rr_7,
                w_i_minus_15_rr_18,
                cols.s0_intermediate,
                is_real,
            );
            cols.s0_intermediate.value
        };

        XorOperation::<AB::F>::eval(
            builder,
            s0_intermediate,
            w_i_minus_15_rs_3,
            cols.s0,
            is_real,
        );
        builder.assert_bool(is_real);
    }
}
