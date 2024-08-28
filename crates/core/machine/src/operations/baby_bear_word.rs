use std::array;

use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;
use sp1_stark::{air::SP1AirBuilder, Word};

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BabyBearWordRangeChecker<T> {
    /// Most sig byte LE bit decomposition.
    pub most_sig_byte_decomp: [T; 8],

    /// The product of the the bits 3 to 5 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_5: T,

    /// The product of the the bits 3 to 6 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_6: T,

    /// The product of the the bits 3 to 7 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_7: T,
}

impl<F: Field> BabyBearWordRangeChecker<F> {
    pub fn populate(&mut self, value: u32) {
        self.most_sig_byte_decomp = array::from_fn(|i| F::from_bool(value & (1 << (i + 24)) != 0));
        self.and_most_sig_byte_decomp_3_to_5 =
            self.most_sig_byte_decomp[3] * self.most_sig_byte_decomp[4];
        self.and_most_sig_byte_decomp_3_to_6 =
            self.and_most_sig_byte_decomp_3_to_5 * self.most_sig_byte_decomp[5];
        self.and_most_sig_byte_decomp_3_to_7 =
            self.and_most_sig_byte_decomp_3_to_6 * self.most_sig_byte_decomp[6];
    }

    pub fn range_check<AB: SP1AirBuilder>(
        builder: &mut AB,
        value: Word<AB::Var>,
        cols: BabyBearWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut recomposed_byte = AB::Expr::zero();
        cols.most_sig_byte_decomp.iter().enumerate().for_each(|(i, value)| {
            builder.when(is_real.clone()).assert_bool(*value);
            recomposed_byte =
                recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << i) * *value;
        });

        builder.when(is_real.clone()).assert_eq(recomposed_byte, value[3]);

        // Range check that value is less than baby bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. BabyBear's modulus is (in big
        // endian binary) 01111000_00000000_00000000_00000001.  So we need to check the
        // following conditions:
        // 1) if most_sig_byte > 01111000, then fail.
        // 2) if most_sig_byte == 01111000, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111000, then pass.
        builder.when(is_real.clone()).assert_zero(cols.most_sig_byte_decomp[7]);

        // Compute the product of the "top bits".
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_5,
            cols.most_sig_byte_decomp[3] * cols.most_sig_byte_decomp[4],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_6,
            cols.and_most_sig_byte_decomp_3_to_5 * cols.most_sig_byte_decomp[5],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_7,
            cols.and_most_sig_byte_decomp_3_to_6 * cols.most_sig_byte_decomp[6],
        );

        let bottom_bits: AB::Expr =
            cols.most_sig_byte_decomp[0..3].iter().map(|bit| (*bit).into()).sum();
        builder
            .when(is_real.clone())
            .when(cols.and_most_sig_byte_decomp_3_to_7)
            .assert_zero(bottom_bits);
        builder
            .when(is_real)
            .when(cols.and_most_sig_byte_decomp_3_to_7)
            .assert_zero(value[0] + value[1] + value[2]);
    }
}
