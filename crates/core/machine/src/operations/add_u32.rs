use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use crate::{air::WordAirBuilder, utils::u32_to_half_word};

/// A set of columns needed to compute the add of two u32s as a u32.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddU32Operation<T> {
    /// The result of `a + b`.
    pub value: [T; 2],
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> AddU32Operation<T> {
    /// Backend-agnostic witgen dual of `populate`: `value = (a + b) mod 2^32` in
    /// two u16 limbs + the limb range checks. Returns the u32 sum as a nat wire.
    pub fn witgen<WB: crate::air::WitnessBuilder<Field = T>>(
        wb: &mut WB,
        cols: &mut AddU32Operation<T>,
        a: WB::Nat,
        b: WB::Nat,
    ) -> WB::Nat {
        let sum = wb.wrapping_add(a, b);
        let expected = wb.bits(sum, 0, 32);
        let e0 = wb.bits(expected, 0, 16);
        let e1 = wb.bits(expected, 16, 16);
        cols.value = [wb.nat_to_field(e0), wb.nat_to_field(e1)];
        wb.add_u16_range_check(e0);
        wb.add_u16_range_check(e1);
        expected
    }
}

impl<F: Field> AddU32Operation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u32: u32, b_u32: u32) -> u32 {
        let expected = a_u32.wrapping_add(b_u32);
        self.value = u32_to_half_word(expected);
        // Range check
        record.add_u16_range_checks(&u32_to_u16_limbs(expected));
        expected
    }

    /// Evaluate the add operation.
    /// Assumes that `a`, `b` are valid u32s of two u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to a valid u32 representing `a + b`.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: [AB::Expr; 2],
        b: [AB::Expr; 2],
        cols: AddU32Operation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::zero();

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + carry
        //  - carry is boolean
        //  - 0 <= value[i] < 2^16
        for i in 0..2 {
            carry = (a[i].clone() + b[i].clone() - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real);
    }
}
