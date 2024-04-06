//! An operation to check if the input word is 0.
//!
//! This is bijective (i.e., returns 1 if and only if the input is 0). It is also worth noting that
//! this operation doesn't do a range check.
use p3_air::AirBuilder;
use p3_field::Field;
use sp1_derive::AlignedBorrow;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;

use super::IsZeroOperation;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroWordOperation<T> {
    /// `IsZeroOperation` to check if each byte in the input word is zero.
    pub is_zero_byte: [IsZeroOperation<T>; WORD_SIZE],

    // `IsZeroOperation` to check whether the sum of is_zero_byte[i].result is 0 or not.
    // The result of whether a word is 0 is sum_is_zero.result.
    pub sum_is_zero: IsZeroOperation<T>,
}

impl<F: Field> IsZeroWordOperation<F> {
    pub fn populate(&mut self, a_u32: u32) -> u32 {
        self.populate_from_field_element(Word::from(a_u32))
    }

    pub fn populate_from_field_element(&mut self, a: Word<F>) -> u32 {
        let mut is_zero = true;
        for i in 0..WORD_SIZE {
            is_zero &= self.is_zero_byte[i].populate_from_field_element(a[i]) == 1;
        }
        // TODO: fix this?
        self.result = F::from_bool(is_zero);
        is_zero as u32
    }

    /// Evaluate IsZeroWordOperation with operand `a`, assuming that is_real has been checked
    /// to be a boolean.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        cols: IsZeroWordOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Calculate whether each byte is 0.
        for i in 0..WORD_SIZE {
            IsZeroOperation::<AB::F>::eval(
                builder,
                a[i].clone(),
                cols.is_zero_byte[i],
                is_real.clone(),
            );
        }

        let sum = cols.is_zero_byte[0].result
            + cols.is_zero_byte[1].result
            + cols.is_zero_byte[2].result
            + cols.is_zero_byte[3].result;

        IsZeroOperation::<AB::F>::eval(builder, sum, cols.sum_is_zero, is_real.clone());
    }

    pub fn result(&self) -> T {
        self.sum_is_zero.result
    }
}
