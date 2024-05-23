use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::air::{SP1AirBuilder, Word, WORD_SIZE};
use crate::runtime::Opcode;

/// Returns `true` if the given `opcode` is a signed operation.
pub fn is_signed_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
pub fn get_quotient_and_remainder(b: u32, c: u32, opcode: Opcode) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        (u32::MAX, b)
    } else if is_signed_operation(opcode) {
        (
            (b as i32).wrapping_div(c as i32) as u32,
            (b as i32).wrapping_rem(c as i32) as u32,
        )
    } else {
        (
            (b as u32).wrapping_div(c as u32) as u32,
            (b as u32).wrapping_rem(c as u32) as u32,
        )
    }
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
pub const fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}

/// Verifies that `abs_value = abs(value)` using `is_negative` as a flag.
///
/// `abs(value) + value = 0` if `value` is negative. `abs(value) = value` otherwise.
///
/// In two's complement arithmetic, the negation involves flipping its bits and adding 1. Therefore,
/// for a negative number, `abs(value) + value` equals 0. This is because `abs(value)` is the two's
/// complement (negation) of `value`. For a positive number, `abs(value)` is the same as `value`.
///
/// The function iterates over each limb of the `value` and `abs_value`, checking the following
/// conditions:
///
/// 1. If `value` is non-negative, it checks that each limb in `value` and `abs_value` is identical.
/// 2. If `value` is negative, it checks that the sum of each corresponding limb in `value` and
///    `abs_value` equals the expected sum for a two's complement representation. The least
///     significant limb (first limb) should add up to `0xff + 1` (to account for the +1 in two's
///     complement negation), and other limbs should add up to `0xff` (as the rest of the limbs just
///     have their bits flipped).
pub fn eval_abs_value<AB>(
    builder: &mut AB,
    value: &Word<AB::Var>,
    abs_value: &Word<AB::Var>,
    is_negative: &AB::Var,
    is_min: &AB::Var,
    is_neg_mult_256: &AB::Var,
) where
    AB: SP1AirBuilder,
{
    for i in 0..WORD_SIZE {
        let exp_sum_if_negative = AB::Expr::from_canonical_u32({
            if i == 0 {
                0xff + 1
            } else {
                0xff
            }
        });
        let exp_sum_if_neg_mult_256 = AB::Expr::from_canonical_u32({
            if i == 0 {
                0x00
            } else if i == 1 {
                0xff + 1
            } else {
                0xff
            }
        });
        let exp_value_if_min = AB::Expr::from_canonical_u32({
            if i != WORD_SIZE - 1 {
                0x00
            } else {
                1 << 7
            }
        });

        // Excluding the special case when value is a negative multiple of 256, we check that the sum of the limbs is `exp_sum_if_negative` if `is_negative` and otherwise check that the limbs are equal.
        builder
            .when_not(*is_neg_mult_256)
            .when(*is_negative)
            .assert_eq(value[i] + abs_value[i], exp_sum_if_negative.clone());

        // In the special case that the value is a negative multiple of 256 (but not -2^31), we check that the first byte of the absolute value is 0,
        // and the sum of the remaining bytes in abs_value and value is as expected.
        builder
            .when(*is_neg_mult_256)
            .when(*is_negative)
            .assert_eq(value[i] + abs_value[i], exp_sum_if_neg_mult_256.clone());

        // In the further special case that the value is the minimum i32 value, we further need to check that the absolute value is again the minimum i32 value.
        builder
            .when(*is_min)
            .when(*is_negative)
            .assert_eq(abs_value[i], exp_value_if_min.clone());

        builder
            .when_not(*is_negative)
            .assert_eq(value[i], abs_value[i]);
    }
}
