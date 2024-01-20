use core::borrow::Borrow;
use core::borrow::BorrowMut;

use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;

/// A set of columns needed to compute the add of four words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add4Operation<T> {
    /// The result of `a + b + c + d`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 4],
}

impl<F: Field> Add4Operation<F> {
    pub fn populate(&mut self, a: u32, b: u32, c: u32, d: u32) -> u32 {
        a.wrapping_add(b).wrapping_add(c).wrapping_add(d)
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        d: Word<AB::Var>,
        cols: Add4Operation<AB::Var>,
    ) {
        // TODO
    }
}
