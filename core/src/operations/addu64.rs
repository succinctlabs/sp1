use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::Word;

use crate::runtime::ExecutionRecord;
use p3_field::AbstractField;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddOperationU64<T> {
    /// The result of `a + b` in two 32bits limbs.
    pub lo: Word<T>,
    pub hi: Word<T>,

    /// Trace.
    pub carry: [T; 7],
}

impl<F: Field> AddOperationU64<F> {
    pub fn populate(
        &mut self,
        record: &mut ExecutionRecord,
        a_lo: u32,
        a_hi: u32,
        b_lo: u32,
        b_hi: u32,
    ) -> (u32, u32) {
        let a = (a_hi as u64) << 32 | a_lo as u64;
        let b = (b_hi as u64) << 32 | b_lo as u64;
        let expected = a.wrapping_add(b);
        self.lo = Word::from(expected as u32);
        self.hi = Word::from((expected >> 32) as u32);
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();

        let mut carry = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        if (a[0] as u32) + (b[0] as u32) > 255 {
            carry[0] = 1;
            self.carry[0] = F::one();
        }
        if (a[1] as u32) + (b[1] as u32) + (carry[0] as u32) > 255 {
            carry[1] = 1;
            self.carry[1] = F::one();
        }
        if (a[2] as u32) + (b[2] as u32) + (carry[1] as u32) > 255 {
            carry[2] = 1;
            self.carry[2] = F::one();
        }
        if (a[3] as u32) + (b[3] as u32) + (carry[2] as u32) > 255 {
            carry[3] = 1;
            self.carry[3] = F::one();
        }
        if (a[4] as u32) + (b[4] as u32) + (carry[3] as u32) > 255 {
            carry[4] = 1;
            self.carry[4] = F::one();
        }
        if (a[5] as u32) + (b[5] as u32) + (carry[4] as u32) > 255 {
            carry[5] = 1;
            self.carry[5] = F::one();
        }
        if (a[6] as u32) + (b[6] as u32) + (carry[5] as u32) > 255 {
            carry[6] = 1;
            self.carry[6] = F::one();
        }

        let base = 256u32;
        let overflow = a[0]
            .wrapping_add(b[0])
            .wrapping_sub(expected.to_le_bytes()[0]) as u32;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            record.add_u8_range_checks(&a);
            record.add_u8_range_checks(&b);
            record.add_u8_range_checks(&expected.to_le_bytes());
        }
        (expected as u32, (expected >> 32) as u32)
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a_lo: Word<AB::Var>,
        a_hi: Word<AB::Var>,
        b_lo: Word<AB::Var>,
        b_hi: Word<AB::Var>,
        cols: AddOperationU64<AB::Var>,
        is_real: AB::Var,
    ) {
        let one = AB::Expr::one();
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a_lo[0] + b_lo[0] - cols.lo[0];
        let overflow_1 = a_lo[1] + b_lo[1] - cols.lo[1] + cols.carry[0];
        let overflow_2 = a_lo[2] + b_lo[2] - cols.lo[2] + cols.carry[1];
        let overflow_3 = a_lo[3] + b_lo[3] - cols.lo[3] + cols.carry[2];
        let overflow_4 = a_hi[0] + b_hi[0] - cols.hi[0] + cols.carry[3];
        let overflow_5 = a_hi[1] + b_hi[1] - cols.hi[1] + cols.carry[4];
        let overflow_6 = a_hi[2] + b_hi[2] - cols.hi[2] + cols.carry[5];
        let overflow_7 = a_hi[3] + b_hi[3] - cols.hi[3] + cols.carry[6];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));
        builder_is_real.assert_zero(overflow_4.clone() * (overflow_4.clone() - base));
        builder_is_real.assert_zero(overflow_5.clone() * (overflow_5.clone() - base));
        builder_is_real.assert_zero(overflow_6.clone() * (overflow_6.clone() - base));
        builder_is_real.assert_zero(overflow_7.clone() * (overflow_7.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));
        builder_is_real.assert_zero(cols.carry[3] * (overflow_3.clone() - base));
        builder_is_real.assert_zero(cols.carry[4] * (overflow_4.clone() - base));
        builder_is_real.assert_zero(cols.carry[5] * (overflow_5.clone() - base));
        builder_is_real.assert_zero(cols.carry[6] * (overflow_6.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());
        builder_is_real.assert_zero((cols.carry[3] - one.clone()) * overflow_3.clone());
        builder_is_real.assert_zero((cols.carry[4] - one.clone()) * overflow_4.clone());
        builder_is_real.assert_zero((cols.carry[5] - one.clone()) * overflow_5.clone());
        builder_is_real.assert_zero((cols.carry[6] - one.clone()) * overflow_6.clone());

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(cols.carry[3]);
        builder_is_real.assert_bool(cols.carry[4]);
        builder_is_real.assert_bool(cols.carry[5]);
        builder_is_real.assert_bool(cols.carry[6]);
        builder_is_real.assert_bool(is_real);

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a_lo.0, is_real);
            builder.slice_range_check_u8(&b_lo.0, is_real);
            builder.slice_range_check_u8(&cols.lo.0, is_real);
            builder.slice_range_check_u8(&a_hi.0, is_real);
            builder.slice_range_check_u8(&b_hi.0, is_real);
            builder.slice_range_check_u8(&cols.hi.0, is_real);
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(a_lo[0] * b_lo[0] * cols.lo[0] - a_lo[0] * b_lo[0] * cols.lo[0]);
    }
}
