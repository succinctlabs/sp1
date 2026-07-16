use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

/// A set of columns needed to compute the NOT of an u32 value.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotU32Operation<T> {
    /// The result of `!x`.
    pub value: [T; 2],
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> NotU32Operation<T> {
    /// Backend-agnostic witgen dual of `populate`: `!x` per u16 limb (no lookups).
    /// Returns `!x` (over u32) as a nat wire.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut NotU32Operation<WB::Field>,
        x: WB::Nat,
    ) -> WB::Nat {
        let ones = wb.const_nat(0xFFFF_FFFF);
        let expected = wb.xor(x, ones);
        let e0 = wb.bits(expected, 0, 16);
        let e1 = wb.bits(expected, 16, 16);
        cols.value = [wb.nat_to_field(e0), wb.nat_to_field(e1)];
        expected
    }
}

impl<F: Field> NotU32Operation<F> {
    pub fn populate(&mut self, x: u32) -> u32 {
        let x_limbs = u32_to_u16_limbs(x);
        self.value[0] = F::from_canonical_u16(!x_limbs[0]);
        self.value[1] = F::from_canonical_u16(!x_limbs[1]);
        !x
    }

    /// Evaluate the NOT operation over a u32 of two u16 limbs.
    /// Assumes that the input is a valid u32 of two u16 limbs.
    /// If `is_real` is non-zero, constrains that the `value` is correct.
    #[allow(unused_variables)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: [AB::Expr; 2],
        cols: NotU32Operation<AB::Var>,
        is_real: impl Into<AB::Expr> + Copy,
    ) {
        // For any u16 limb b, b + !b = 0xFFFF.
        for i in 0..2 {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i].clone(), AB::F::from_canonical_u16(u16::MAX));
        }
    }
}
