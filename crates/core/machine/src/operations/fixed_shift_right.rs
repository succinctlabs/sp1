use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

use crate::utils::u32_to_half_word;

/// A set of columns needed to compute `>>` of an u32 with a fixed offset R.
///
/// Note that we decompose shifts into a limb shift and a bit shift.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedShiftRightOperation<T> {
    /// The output value.
    pub value: [T; 2],

    /// The higher bits of each limb.
    pub higher_limb: [T; 2],
}

impl<F: Field> FixedShiftRightOperation<F> {
    pub const fn nb_limbs_to_shift(rotation: usize) -> usize {
        rotation / 16
    }

    pub const fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 16
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (16 - nb_bits_to_shift)
    }
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> FixedShiftRightOperation<T> {
    /// Backend-agnostic witgen dual of `populate` (fixed shift amount, baked into
    /// the recorded op-DAG). Returns `input >> rotation` as a nat wire.
    pub fn witgen<WB: crate::air::WitnessBuilder<Field = T>>(
        wb: &mut WB,
        cols: &mut FixedShiftRightOperation<T>,
        input: WB::Nat,
        rotation: usize,
    ) -> WB::Nat {
        let nb_limbs_to_shift = rotation / 16;
        let nb_bits_to_shift = rotation % 16;
        assert!(nb_bits_to_shift > 0, "shift must not be a multiple of 16");
        let zero = wb.const_nat(0);
        let expected = wb.bits(input, rotation as u32, 32 - rotation as u32);
        let e0 = wb.bits(expected, 0, 16);
        let e1 = wb.bits(expected, 16, 16);
        cols.value = [wb.nat_to_field(e0), wb.nat_to_field(e1)];
        // Limb shift, then per-limb bit split (mirrors `populate`).
        let l0 = wb.bits(input, 0, 16);
        let l1 = wb.bits(input, 16, 16);
        let word = match nb_limbs_to_shift {
            0 => [l0, l1],
            1 => [l1, zero],
            _ => [zero, zero],
        };
        for i in [1usize, 0] {
            let limb = word[i];
            let lower = wb.bits(limb, 0, nb_bits_to_shift as u32);
            let higher = wb.bits(limb, nb_bits_to_shift as u32, (16 - nb_bits_to_shift) as u32);
            cols.higher_limb[i] = wb.nat_to_field(higher);
            wb.add_bit_range_check(lower, nb_bits_to_shift as u8);
            wb.add_bit_range_check(higher, (16 - nb_bits_to_shift) as u8);
        }
        expected
    }
}

impl<F: Field> FixedShiftRightOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, input: u32, rotation: usize) -> u32 {
        let input_limbs = u32_to_u16_limbs(input);
        let expected = input >> rotation;
        self.value = u32_to_half_word(expected);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_limbs_to_shift = Self::nb_limbs_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);

        // Perform the limb shift.
        let mut word = [0u16; 2];
        for i in 0..2 {
            if i + nb_limbs_to_shift < 2 {
                word[i] = input_limbs[i + nb_limbs_to_shift];
            }
        }

        for i in (0..2).rev() {
            let limb = word[i];
            let lower_limb = (limb & ((1 << nb_bits_to_shift) - 1)) as u16;
            let higher_limb = (limb >> nb_bits_to_shift) as u16;
            self.higher_limb[i] = F::from_canonical_u16(higher_limb);
            record.add_bit_range_check(lower_limb, nb_bits_to_shift as u8);
            record.add_bit_range_check(higher_limb, (16 - nb_bits_to_shift) as u8);
        }

        expected
    }

    /// Evaluates the u32 fixed shift right. Constrains that `is_real` is boolean.
    /// If `is_real` is true, the result `value` will be the correct result with two u16 limbs.
    /// This function assumes that the `input` is a u32 with valid two u16 limbs.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input: [AB::Var; 2],
        rotation: usize,
        cols: FixedShiftRightOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_limbs_to_shift = Self::nb_limbs_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the limb shift.
        let input_limbs_shifted: [AB::Expr; 2] = std::array::from_fn(|i| {
            if i + nb_limbs_to_shift < 2 {
                input[i + nb_limbs_to_shift].into()
            } else {
                AB::Expr::zero()
            }
        });

        // For each limb, constrain the lower and higher parts of the limb.
        let mut lower_limb = [AB::Expr::zero(), AB::Expr::zero()];
        for i in 0..2 {
            let limb = input_limbs_shifted[i].clone();

            // Break down the limb into lower and higher parts.
            //  - `limb = lower_limb + higher_limb * 2^bit_shift`
            //  - `lower_limb < 2^(bit_shift)`
            //  - `higher_limb < 2^(16 - bit_shift)`
            lower_limb[i] =
                limb - cols.higher_limb[i] * AB::Expr::from_canonical_u32(1 << nb_bits_to_shift);

            // Check that `lower_limb < 2^(bit_shift)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                lower_limb[i].clone(),
                AB::F::from_canonical_u32(nb_bits_to_shift as u32),
                AB::Expr::zero(),
                is_real,
            );
            // Check that `higher_limb < 2^(16 - bit_shift)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                cols.higher_limb[i],
                AB::Expr::from_canonical_u32(16 - nb_bits_to_shift as u32),
                AB::Expr::zero(),
                is_real,
            );
        }

        // Constrain the resulting value using the lower and higher parts.
        builder.when(is_real).assert_eq(cols.value[1], cols.higher_limb[1]);
        builder.when(is_real).assert_eq(
            cols.value[0],
            cols.higher_limb[0] + lower_limb[1].clone() * carry_multiplier,
        );
    }
}
