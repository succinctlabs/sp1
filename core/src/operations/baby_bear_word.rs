use std::array;

use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use crate::{air::Word, stark::SP1AirBuilder};

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BabyBearWord<T> {
    /// The babybear element in word format.
    pub value: Word<T>,

    /// Most sig byte LE bit decomposition.
    pub most_sig_byte_decomp: [T; 8],
}

impl<F: Field> BabyBearWord<F> {
    pub fn populate(&mut self, value: u32) {
        self.value = value.into();
        self.most_sig_byte_decomp = array::from_fn(|i| F::from_bool(value & (1 << (i + 24)) != 0));
    }

    pub fn range_check<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: BabyBearWord<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut recomposed_byte = AB::Expr::zero();
        cols.most_sig_byte_decomp
            .iter()
            .enumerate()
            .for_each(|(i, value)| {
                builder.when(is_real.clone()).assert_bool(*value);

                recomposed_byte =
                    recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << i) * *value;
            });

        builder
            .when(is_real.clone())
            .assert_eq(recomposed_byte, cols.value[3]);

        // Range check that value is less than baby bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. BabyBear's modulus is (in big endian binary)
        // 01111000_00000000_00000000_00000001.  So we need to check the following conditions:
        // 1) if most_sig_byte > 01111000, then fail.
        // 2) if most_sig_byte == 01111000, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111000, then pass.
        builder
            .when(is_real.clone())
            .assert_bool(cols.most_sig_byte_decomp[7]);
        let top_bits: AB::Expr = cols.most_sig_byte_decomp[3..7]
            .iter()
            .map(|bit| (*bit).into())
            .sum();
        let bottom_bits: AB::Expr = cols.most_sig_byte_decomp[0..3]
            .iter()
            .map(|bit| (*bit).into())
            .sum();
        builder
            .when(is_real.clone())
            .when(top_bits.clone())
            .assert_zero(bottom_bits);
        builder
            .when(is_real)
            .when(top_bits)
            .assert_zero(cols.value[0] + cols.value[1] + cols.value[2]);
    }
}
