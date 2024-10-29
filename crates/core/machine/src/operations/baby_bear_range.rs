use std::array;

use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::SP1AirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BabyBearBitDecomposition<T> {
    /// The bit decoposition of the`value`.
    pub bits: [T; 32],

    /// The product of the the bits 3 to 5 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_5: T,

    /// The product of the the bits 3 to 6 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_6: T,

    /// The product of the the bits 3 to 7 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_3_to_7: T,
}

impl<F: Field> BabyBearBitDecomposition<F> {
    pub fn populate(&mut self, value: u32) {
        self.bits = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
        let most_sig_byte_decomp = &self.bits[24..32];
        self.and_most_sig_byte_decomp_3_to_5 = most_sig_byte_decomp[3] * most_sig_byte_decomp[4];
        self.and_most_sig_byte_decomp_3_to_6 =
            self.and_most_sig_byte_decomp_3_to_5 * most_sig_byte_decomp[5];
        self.and_most_sig_byte_decomp_3_to_7 =
            self.and_most_sig_byte_decomp_3_to_6 * most_sig_byte_decomp[6];
    }

    pub fn range_check<AB: SP1AirBuilder>(
        builder: &mut AB,
        value: AB::Var,
        cols: BabyBearBitDecomposition<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut reconstructed_value = AB::Expr::zero();
        for (i, bit) in cols.bits.iter().enumerate() {
            builder.when(is_real.clone()).assert_bool(*bit);
            reconstructed_value =
                reconstructed_value.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // Assert that bits2num(bits) == value.
        builder.when(is_real.clone()).assert_eq(reconstructed_value, value);

        // Range check that value is less than baby bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. BabyBear's modulus is (in big
        // endian binary) 01111000_00000000_00000000_00000001.  So we need to check the
        // following conditions:
        // 1) if most_sig_byte > 01111000, then fail.
        // 2) if most_sig_byte == 01111000, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111000, then pass.
        let most_sig_byte_decomp = &cols.bits[24..32];
        builder.when(is_real.clone()).assert_zero(most_sig_byte_decomp[7]);

        // Compute the product of the "top bits".
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_5,
            most_sig_byte_decomp[3] * most_sig_byte_decomp[4],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_6,
            cols.and_most_sig_byte_decomp_3_to_5 * most_sig_byte_decomp[5],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_3_to_7,
            cols.and_most_sig_byte_decomp_3_to_6 * most_sig_byte_decomp[6],
        );

        // If the top bits are all 0, then the lower bits must all be 0.
        let mut lower_bits_sum: AB::Expr = AB::Expr::zero();
        for bit in cols.bits[0..27].iter() {
            lower_bits_sum = lower_bits_sum + *bit;
        }
        builder
            .when(is_real)
            .when(cols.and_most_sig_byte_decomp_3_to_7)
            .assert_zero(lower_bits_sum);
    }
}
