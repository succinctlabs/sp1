use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

/// A set of columns needed to compute `rotateright` of a u32 with a fixed offset R.
///
/// Note that we decompose rotate into a limb rotate and a bit rotate.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedRotateRightOperation<T> {
    /// The output value.
    pub value: [T; 2],

    /// The higher bits of each limb.
    pub higher_limb: [T; 2],
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> FixedRotateRightOperation<T> {
    /// See [`FixedRotateRightOperation::witgen_generic`] — hoisted here so the
    /// column type only needs `Copy` (the builder computes the field values).
    pub fn witgen<WB: crate::air::WitnessBuilder<Field = T>>(
        wb: &mut WB,
        cols: &mut FixedRotateRightOperation<T>,
        input: WB::Nat,
        rotation: usize,
    ) -> WB::Nat {
        Self::witgen_impl(wb, cols, input, rotation)
    }

    /// Backend-agnostic witgen dual of `populate`. `rotation` is a Rust-level
    /// constant (each call site rotates by a fixed amount), so the recorded op-DAG
    /// bakes in the limb/bit split. Returns the rotated u32 as a nat wire.
    fn witgen_impl<WB: crate::air::WitnessBuilder<Field = T>>(
        wb: &mut WB,
        cols: &mut FixedRotateRightOperation<T>,
        input: WB::Nat,
        rotation: usize,
    ) -> WB::Nat {
        let nb_limbs_to_rotate = rotation / 16;
        let nb_bits_to_rotate = rotation % 16;
        assert!(nb_bits_to_rotate > 0, "rotation must not be a multiple of 16");
        // expected = input.rotate_right(rotation) over u32.
        let r = (rotation % 32) as u32;
        let low = wb.bits(input, r, 32 - r);
        let high = wb.bits(input, 0, r);
        let shift = wb.const_nat((32 - r) as u64);
        let high_shifted = wb.shl(high, shift);
        let expected = wb.wrapping_add(low, high_shifted);
        let e0 = wb.bits(expected, 0, 16);
        let e1 = wb.bits(expected, 16, 16);
        cols.value = [wb.nat_to_field(e0), wb.nat_to_field(e1)];
        // Limb rotate, then per-limb bit split (mirrors `populate`).
        let l0 = wb.bits(input, 0, 16);
        let l1 = wb.bits(input, 16, 16);
        let rotated = if nb_limbs_to_rotate.is_multiple_of(2) { [l0, l1] } else { [l1, l0] };
        for i in [1usize, 0] {
            let limb = rotated[i];
            let lower = wb.bits(limb, 0, nb_bits_to_rotate as u32);
            let higher = wb.bits(limb, nb_bits_to_rotate as u32, (16 - nb_bits_to_rotate) as u32);
            cols.higher_limb[i] = wb.nat_to_field(higher);
            wb.add_bit_range_check(lower, nb_bits_to_rotate as u8);
            wb.add_bit_range_check(higher, (16 - nb_bits_to_rotate) as u8);
        }
        expected
    }
}

impl<F: Field> FixedRotateRightOperation<F> {
    pub const fn nb_limbs_to_rotate(rotation: usize) -> usize {
        rotation / 16
    }

    pub const fn nb_bits_to_rotate(rotation: usize) -> usize {
        rotation % 16
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_rotate = Self::nb_bits_to_rotate(rotation);
        1 << (16 - nb_bits_to_rotate)
    }

    pub fn populate(&mut self, record: &mut impl ByteRecord, input: u32, rotation: usize) -> u32 {
        let input_limbs = u32_to_u16_limbs(input);
        let expected = input.rotate_right(rotation as u32);
        self.value = [
            F::from_canonical_u16((expected & 0xFFFF) as u16),
            F::from_canonical_u16((expected >> 16) as u16),
        ];

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_limbs_to_rotate = Self::nb_limbs_to_rotate(rotation);
        let nb_bits_to_rotate = Self::nb_bits_to_rotate(rotation);

        // Perform the limb rotate.
        let input_limbs_rotated =
            [input_limbs[nb_limbs_to_rotate % 2], input_limbs[(1 + nb_limbs_to_rotate) % 2]];

        for i in (0..2).rev() {
            let limb = input_limbs_rotated[i];
            let lower_limb = (limb & ((1 << nb_bits_to_rotate) - 1)) as u16;
            let higher_limb = (limb >> nb_bits_to_rotate) as u16;
            self.higher_limb[i] = F::from_canonical_u16(higher_limb);
            record.add_bit_range_check(lower_limb, nb_bits_to_rotate as u8);
            record.add_bit_range_check(higher_limb, (16 - nb_bits_to_rotate) as u8);
        }

        expected
    }

    /// Evaluates the u32 fixed rotate right. Constrains that `is_real` is boolean.
    /// If `is_real` is true, the result `value` will be the correct result with two u16 limbs.
    /// This function assumes that the `input` is a u32 with valid two u16 limbs.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input: [AB::Var; 2],
        rotation: usize,
        cols: FixedRotateRightOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Constrains that `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_limbs_to_rotate = Self::nb_limbs_to_rotate(rotation);
        let nb_bits_to_rotate = Self::nb_bits_to_rotate(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the limb rotate.
        let input_limbs_rotated =
            [input[nb_limbs_to_rotate % 2], input[(1 + nb_limbs_to_rotate) % 2]];

        // For each limb, constrain the lower and higher parts of the limb.
        let mut lower_limb = [AB::Expr::zero(), AB::Expr::zero()];
        for i in 0..2 {
            let limb = input_limbs_rotated[i];

            // Break down the limb into lower and higher parts.
            //  - `limb = lower_limb + higher_limb * 2^bit_rotate`
            //  - `lower_limb < 2^(bit_rotate)`
            //  - `higher_limb < 2^(16 - bit_rotate)`
            lower_limb[i] =
                limb - cols.higher_limb[i] * AB::Expr::from_canonical_u32(1 << nb_bits_to_rotate);

            // Check that `lower_limb < 2^(bit_rotate)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                lower_limb[i].clone(),
                AB::F::from_canonical_u32(nb_bits_to_rotate as u32),
                AB::Expr::zero(),
                is_real,
            );
            // Check that `higher_limb < 2^(16 - bit_rotate)`
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                cols.higher_limb[i],
                AB::Expr::from_canonical_u32(16 - nb_bits_to_rotate as u32),
                AB::Expr::zero(),
                is_real,
            );
        }

        // Constrain the resulting value using the lower and higher parts.
        builder.when(is_real).assert_eq(
            cols.value[1],
            cols.higher_limb[1] + lower_limb[0].clone() * carry_multiplier,
        );
        builder.when(is_real).assert_eq(
            cols.value[0],
            cols.higher_limb[0] + lower_limb[1].clone() * carry_multiplier,
        );
    }
}
