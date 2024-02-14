use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::operations::AndOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

/// `maj := (a and b) xor (a and c) xor (b and c)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MajOperation<T> {
    pub a_and_b: AndOperation<T>,
    pub a_and_c: AndOperation<T>,
    pub b_and_c: AndOperation<T>,
    pub maj_intermediate: XorOperation<T>,
    pub maj: XorOperation<T>,
}

impl<F: Field> MajOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, a: u32, b: u32, c: u32) -> u32 {
        let a_and_b = self.a_and_b.populate(record, a, b);
        let a_and_c = self.a_and_c.populate(record, a, c);
        let b_and_c = self.b_and_c.populate(record, b, c);
        let maj_intermediate = self.maj_intermediate.populate(record, a_and_b, a_and_c);

        self.maj.populate(record, maj_intermediate, b_and_c)
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        cols: MajOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Maj := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22).
        let a_and_b = {
            AndOperation::<AB::F>::eval(builder, a, b, cols.a_and_b, is_real);
            cols.a_and_b.value
        };
        let a_and_c = {
            AndOperation::<AB::F>::eval(builder, a, c, cols.a_and_c, is_real);
            cols.a_and_c.value
        };
        let b_and_c = {
            AndOperation::<AB::F>::eval(builder, b, c, cols.b_and_c, is_real);
            cols.b_and_c.value
        };
        let maj_intermediate = {
            XorOperation::<AB::F>::eval(builder, a_and_b, a_and_c, cols.maj_intermediate, is_real);
            cols.maj_intermediate.value
        };
        XorOperation::<AB::F>::eval(builder, maj_intermediate, b_and_c, cols.maj, is_real);
        builder.assert_bool(is_real);
    }
}
