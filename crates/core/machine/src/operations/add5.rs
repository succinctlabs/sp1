use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use sp1_core_executor::events::ByteRecord;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::SP1AirBuilder, Word};

use crate::air::WordAirBuilder;

/// A set of columns needed to compute the sum of five words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add5Operation<T> {
    /// The result of `a + b + c + d + e`.
    pub value: Word<T>,

    /// Indicates if the carry for the `i`th limb is 0.
    pub is_carry_0: Word<T>,

    /// Indicates if the carry for the `i`th limb is 1.
    pub is_carry_1: Word<T>,

    /// Indicates if the carry for the `i`th limb is 2.
    pub is_carry_2: Word<T>,

    /// Indicates if the carry for the `i`th limb is 3.
    pub is_carry_3: Word<T>,

    /// Indicates if the carry for the `i`th limb is 4. The carry when adding 5 words is at most 4.
    pub is_carry_4: Word<T>,

    /// The carry for the `i`th limb.
    pub carry: Word<T>,
}

impl<F: Field> Add5Operation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
        e_u32: u32,
    ) -> u32 {
        let expected =
            a_u32.wrapping_add(b_u32).wrapping_add(c_u32).wrapping_add(d_u32).wrapping_add(e_u32);

        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let c = c_u32.to_le_bytes();
        let d = d_u32.to_le_bytes();
        let e = e_u32.to_le_bytes();

        let base = 256;
        let mut carry = [0u8, 0u8, 0u8, 0u8, 0u8];
        for i in 0..WORD_SIZE {
            let mut res =
                (a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32) + (e[i] as u32);
            if i > 0 {
                res += carry[i - 1] as u32;
            }
            carry[i] = (res / base) as u8;
            self.is_carry_0[i] = F::from_bool(carry[i] == 0);
            self.is_carry_1[i] = F::from_bool(carry[i] == 1);
            self.is_carry_2[i] = F::from_bool(carry[i] == 2);
            self.is_carry_3[i] = F::from_bool(carry[i] == 3);
            self.is_carry_4[i] = F::from_bool(carry[i] == 4);
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= 4);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(res % base));
        }

        // Range check.
        {
            record.add_u8_range_checks(shard, &a);
            record.add_u8_range_checks(shard, &b);
            record.add_u8_range_checks(shard, &c);
            record.add_u8_range_checks(shard, &d);
            record.add_u8_range_checks(shard, &e);
            record.add_u8_range_checks(shard, &expected.to_le_bytes());
        }

        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        words: &[Word<AB::Var>; 5],
        is_real: AB::Var,
        cols: Add5Operation<AB::Var>,
    ) {
        builder.assert_bool(is_real);
        // Range check each byte.
        {
            words.iter().for_each(|word| builder.slice_range_check_u8(&word.0, is_real));
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }
        let mut builder_is_real = builder.when(is_real);

        // Each value in is_carry_{0,1,2,3,4} is 0 or 1, and exactly one of them is 1 per digit.
        {
            for i in 0..WORD_SIZE {
                builder_is_real.assert_bool(cols.is_carry_0[i]);
                builder_is_real.assert_bool(cols.is_carry_1[i]);
                builder_is_real.assert_bool(cols.is_carry_2[i]);
                builder_is_real.assert_bool(cols.is_carry_3[i]);
                builder_is_real.assert_bool(cols.is_carry_4[i]);
                builder_is_real.assert_eq(
                    cols.is_carry_0[i]
                        + cols.is_carry_1[i]
                        + cols.is_carry_2[i]
                        + cols.is_carry_3[i]
                        + cols.is_carry_4[i],
                    AB::Expr::one(),
                );
            }
        }

        // Calculates carry from is_carry_{0,1,2,3,4}.
        {
            let one = AB::Expr::one();
            let two = AB::F::from_canonical_u32(2);
            let three = AB::F::from_canonical_u32(3);
            let four = AB::F::from_canonical_u32(4);

            for i in 0..WORD_SIZE {
                builder_is_real.assert_eq(
                    cols.carry[i],
                    cols.is_carry_1[i] * one.clone()
                        + cols.is_carry_2[i] * two
                        + cols.is_carry_3[i] * three
                        + cols.is_carry_4[i] * four,
                );
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            let base = AB::F::from_canonical_u32(256);
            // For each limb, assert that difference between the carried result and the non-carried
            // result is the product of carry and base.
            for i in 0..WORD_SIZE {
                let mut overflow: AB::Expr = AB::F::zero().into();
                for word in words {
                    overflow = overflow.clone() + word[i].into();
                }
                overflow = overflow.clone() - cols.value[i].into();

                if i > 0 {
                    overflow = overflow.clone() + cols.carry[i - 1].into();
                }
                builder_is_real.assert_eq(cols.carry[i] * base, overflow.clone());
            }
        }
    }
}
