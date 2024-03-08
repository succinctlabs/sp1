use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::{WordU64, WORD_U64_SIZE};

use crate::runtime::ExecutionRecord;
use p3_field::AbstractField;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddOperationU64<T> {
    /// The result of two u64 `a + b`.
    pub value: WordU64<T>,

    /// Trace.
    pub carry: [T; WORD_U64_SIZE - 1],
}

impl<F: Field> AddOperationU64<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, a_u64: u64, b_u64: u64) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        self.value = WordU64::from(expected);
        let a = a_u64.to_le_bytes();
        let b = b_u64.to_le_bytes();

        let mut carry = [0u8; WORD_U64_SIZE - 1];
        if (a[0] as u32) + (b[0] as u32) > 255 {
            carry[0] = 1;
            self.carry[0] = F::one();
        }
        for i in 1..WORD_U64_SIZE - 1 {
            if (a[i] as u32) + (b[i] as u32) + (carry[i - 1] as u32) > 255 {
                carry[i] = 1;
                self.carry[i] = F::one();
            };
        }

        let base = 256u64;
        let overflow = a[0]
            .wrapping_add(b[0])
            .wrapping_sub(expected.to_le_bytes()[0]) as u64;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            record.add_u8_range_checks(&a);
            record.add_u8_range_checks(&b);
            record.add_u8_range_checks(&expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: WordU64<AB::Var>,
        b: WordU64<AB::Var>,
        cols: AddOperationU64<AB::Var>,
        is_real: AB::Var,
    ) {
        let one = AB::Expr::one();
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real);

        // For each `u8` limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base. The least significant limb is handled separately as it
        // does not have a carry.
        let mut overflow_prev_limb = a[0] + b[0] - cols.value[0];
        builder_is_real
            .assert_zero(overflow_prev_limb.clone() * (overflow_prev_limb.clone() - base));

        // handling the rest of the limbs.
        for i in 1..7 {
            let overflow_curr_limb = a[i] + b[i] - cols.value[i] + cols.carry[i - 1];
            builder_is_real
                .assert_zero(overflow_curr_limb.clone() * (overflow_curr_limb.clone() - base));

            // If the carry is one, then the overflow must be the base. If the carry is not one, then
            // the overflow must be zero.
            builder_is_real.assert_zero(
                cols.carry[i - 1] * (overflow_prev_limb.clone() - base)
                    + (one.clone() - cols.carry[i - 1]) * overflow_prev_limb.clone(),
            );

            // update the overflow_prev_limb for the next iteration.
            overflow_prev_limb = overflow_curr_limb;
        }

        // assert that if carry is one, then the overflow must be the base. If the carry is not one,
        // then the overflow must be zero for the most significant limb.
        builder_is_real.assert_zero(
            cols.carry[6] * (overflow_prev_limb.clone() - base)
                + (one.clone() - cols.carry[6]) * overflow_prev_limb.clone(),
        );

        // Assert that the carry is either zero or one.
        for i in 0..7 {
            builder_is_real.assert_bool(cols.carry[i]);
        }

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, is_real);
            builder.slice_range_check_u8(&b.0, is_real);
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(a[0] * b[0] * cols.value[0] - a[0] * b[0] * cols.value[0]);
    }
}
