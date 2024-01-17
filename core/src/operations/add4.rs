use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::AbstractField;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::air::WORD_SIZE;
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode;

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
    pub fn populate(&mut self, a_u32: u32, b_u32: u32, c_u32: u32, d_u32: u32) -> u32 {
        let expected = a_u32
            .wrapping_add(b_u32)
            .wrapping_add(c_u32)
            .wrapping_add(d_u32);
        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let c = c_u32.to_le_bytes();
        let d = d_u32.to_le_bytes();

        let base = 256;
        let mut carry = [0u8, 0u8, 0u8, 0u8];
        for i in 0..WORD_SIZE {
            let mut res = (a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32);
            if i > 0 {
                res += carry[i - 1] as u32;
            }
            carry[i] = (res / base) as u8;
            debug_assert!(carry[i] <= 3);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(res % base));

            // TODO: Use is_1, is_2, is_3, is_4 to check that carry[i] is in the correct range.
        }
        expected
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
        // let one = AB::Expr::one();
        // let base = AB::F::from_canonical_u32(256);

        // // For each limb, assert that difference between the carried result and the non-carried
        // // result is the product of carry and base.
        // for i in 0..WORD_SIZE {
        //     let mut overflow = a[i] + b[i] + c[i] + d[i] - cols.value[i];
        //     if i > 0 {
        //         overflow += cols.carry[i - 1].into();
        //     }
        //     builder.assert_eq(cols.carry[i] * base, overflow.clone());
        // }

        // // Assert that the carry is either zero or one.
        // builder.assert_bool(cols.carry[0]);
        // for i in 0..WORD_SIZE {
        //     // TODO: Change this!
        //     // Make sure that carry[i] = 0, 1, 2, 3.
        //     // TODO: Use is_1, is_2, is_3, is_4 to check that carry[i] is in the correct range.
        // }

        // // Degree 3 constraint to avoid "OodEvaluationMismatch".
        // builder.assert_zero(a[0] * b[0] * cols.value[0] - a[0] * b[0] * cols.value[0]);
    }
}
