use sp1_core_executor::events::ByteRecord;
use sp1_stark::{air::SP1AirBuilder, Word};

use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use crate::air::WordAirBuilder;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddOperation<T> {
    /// The result of `a + b`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> AddOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a_u32: u32,
        b_u32: u32,
    ) -> u32 {
        let expected = a_u32.wrapping_add(b_u32);
        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();

        let mut carry = [0u8, 0u8, 0u8];
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

        let base = 256u32;
        let overflow = a[0].wrapping_add(b[0]).wrapping_sub(expected.to_le_bytes()[0]) as u32;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            record.add_u8_range_checks(shard, &a);
            record.add_u8_range_checks(shard, &b);
            record.add_u8_range_checks(shard, &expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::one();
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real.clone());

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(is_real.clone());

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, is_real.clone());
            builder.slice_range_check_u8(&b.0, is_real.clone());
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }
    }
}
