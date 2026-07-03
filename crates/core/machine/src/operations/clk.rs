use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_hypercube::air::SP1AirBuilder;

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use crate::air::WordAirBuilder;

/// A set of columns needed to increment the clk and handle the carry.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ClkOperation<T> {
    next_clk_16_24: T,
    next_clk_0_16: T,
    is_overflow: T,
}

impl<T: Copy> ClkOperation<T> {
    pub fn next_clk_high<AB>(&self, clk_high: AB::Var) -> AB::Expr
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        clk_high.into() + self.is_overflow
    }

    pub fn next_clk_low<AB>(&self) -> AB::Expr
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        self.next_clk_0_16.into()
            + self.next_clk_16_24.into() * AB::Expr::from_canonical_u32(1 << 16)
    }
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> ClkOperation<T> {
    /// Backend-agnostic witgen dual of `populate`: decompose `next_clk = clk +
    /// increment` into 16/8 limbs and the 24-bit carry flag, with the canonicity
    /// range checks.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut ClkOperation<WB::Field>,
        clk: WB::Nat,
        increment: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let next_clk = wb.wrapping_add(clk.clone(), increment);
        let n0 = wb.bits(next_clk.clone(), 0, 16);
        cols.next_clk_0_16 = wb.nat_to_field(n0.clone());
        let n16 = wb.bits(next_clk.clone(), 16, 8);
        cols.next_clk_16_24 = wb.nat_to_field(n16.clone());
        // is_overflow = (next_clk >> 24) != (clk >> 24).
        let next_hi = wb.bits(next_clk, 24, 40);
        let cur_hi = wb.bits(clk, 24, 40);
        let hi_eq = wb.eq(next_hi, cur_hi);
        let is_overflow = wb.eq(hi_eq, zero.clone());
        cols.is_overflow = wb.nat_to_field(is_overflow);

        wb.add_bit_range_check(n0, 16);
        wb.add_u8_range_check(n16, zero);
    }
}

impl<F: Field> ClkOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, clk: u64, increment: u64) {
        let next_clk = clk + increment;
        let next_clk_16_24 = ((next_clk >> 16) & 0xFF) as u8;
        let next_clk_0_16 = (next_clk & 0xFFFF) as u16;

        let is_overflow = (next_clk >> 24) != (clk >> 24);
        self.is_overflow = F::from_canonical_u8(is_overflow as u8);
        self.next_clk_16_24 = F::from_canonical_u8(next_clk_16_24);
        self.next_clk_0_16 = F::from_canonical_u16(next_clk_0_16);

        record.add_bit_range_check(next_clk_0_16, 16);
        record.add_u8_range_checks(&[next_clk_16_24, 0]);
    }

    // Check that `clk_low + increment` overflows 24 bits.
    // Checks that `is_real` is boolean. If `is_real` is true, `next_clk` limbs are correct
    // low 24 bits of `clk_low + increment`, and `is_overflow` is the carry.
    // This function assumes that `clk_low` and `increment` is within 24 bits.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_low: AB::Expr,
        increment: AB::Expr,
        cols: ClkOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Check that `is_real` is boolean.
        builder.assert_bool(is_real.clone());

        // Check that `is_overflow` is boolean.
        builder.assert_bool(cols.is_overflow);

        // Constrain the `next_clk_low` value.
        // If `is_overflow` is false, then it's equal to `clk_low + increment`.
        // If `is_overflow` is true, then it's equal to `clk_low + increment - 2^24`.
        builder.when(is_real.clone()).assert_eq(
            clk_low.clone() + increment.clone()
                - cols.is_overflow.into() * AB::Expr::from_canonical_u32(1 << 24),
            cols.next_clk_low::<AB>(),
        );

        // Constrain that `next_clk_low` is a valid 24 bit value by decomposing into two limbs.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            cols.next_clk_0_16.into(),
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            is_real.clone(),
        );
        builder
            .slice_range_check_u8(&[cols.next_clk_16_24.into(), AB::Expr::zero()], is_real.clone());
    }
}
