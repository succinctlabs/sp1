use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;

/// A set of columns needed to compute the add of five words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add5Operation<T> {
    /// The result of `a + b + c + d + e`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> Add5Operation<F> {
    pub fn populate(&mut self, a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
        let expected = a
            .wrapping_add(b)
            .wrapping_add(c)
            .wrapping_add(d)
            .wrapping_add(e);
        self.value = Word::from(expected);
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        d: Word<AB::Var>,
        e: Word<AB::Var>,
        cols: Add5Operation<AB::Var>,
    ) {
        // TODO
    }
}
