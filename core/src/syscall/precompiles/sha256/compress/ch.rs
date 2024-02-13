use core::borrow::Borrow;
use core::borrow::BorrowMut;
use curta_derive::AlignedBorrow;
use p3_field::Field;
use std::mem::size_of;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::operations::AndOperation;
use crate::operations::NotOperation;
use crate::operations::XorOperation;
use crate::runtime::ExecutionRecord;

/// `ch := (e and f) xor ((not e) and g)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ChOperation<T> {
    pub e_and_f: AndOperation<T>,
    pub e_not: NotOperation<T>,
    pub e_not_and_g: AndOperation<T>,
    pub ch: XorOperation<T>,
}

impl<F: Field> ChOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, e: u32, f: u32, g: u32) -> u32 {
        let e_and_f = self.e_and_f.populate(record, e, f);
        let e_not = self.e_not.populate(record, e);
        let e_not_and_g = self.e_not_and_g.populate(record, e_not, g);
        self.ch.populate(record, e_and_f, e_not_and_g)
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        e: Word<AB::Var>,
        f: Word<AB::Var>,
        g: Word<AB::Var>,
        cols: ChOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // ch := (e and f) xor ((not e) and g).
        AndOperation::<AB::F>::eval(builder, e, f, cols.e_and_f, is_real);
        NotOperation::<AB::F>::eval(builder, e, cols.e_not, is_real);
        AndOperation::<AB::F>::eval(builder, cols.e_not.value, g, cols.e_not_and_g, is_real);
        XorOperation::<AB::F>::eval(
            builder,
            cols.e_and_f.value,
            cols.e_not_and_g.value,
            cols.ch,
            is_real,
        );

        builder.assert_bool(is_real);
    }
}
