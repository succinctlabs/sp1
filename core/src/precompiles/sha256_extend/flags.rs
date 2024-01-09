use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;
use std::borrow::Borrow;

use p3_matrix::MatrixRowSlices;

use crate::air::CurtaAirBuilder;

use super::ShaExtendCols;

pub(crate) fn populate_flags<F: PrimeField>(i: usize, cols: &mut ShaExtendCols<F>) {
    // The generator of the multiplicative subgroup.
    let g = F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

    // Populate the columns needed to keep track of cycles of 16.
    cols.cycle_16 = g.exp_u64((i + 1) as u64);
    cols.cycle_16_minus_one = cols.cycle_16 - F::one();
    cols.cycle_16_minus_one_inv = if cols.cycle_16_minus_one == F::zero() {
        F::one()
    } else {
        cols.cycle_16_minus_one.inverse()
    };
    cols.cycle_16_minus_one_is_zero = F::from_bool(cols.cycle_16_minus_one == F::zero());

    // Populate the columns needed to keep track of cycles of 13.
    let j = i % 48;
    cols.i = F::from_canonical_usize(j);
    cols.cycle_3[0] = F::from_bool(j < 16);
    cols.cycle_3[1] = F::from_bool(16 <= j && j < 32);
    cols.cycle_3[2] = F::from_bool(32 <= j && j < 48);
}

pub(crate) fn eval_flags<AB: CurtaAirBuilder>(builder: &mut AB) {
    let main = builder.main();
    let local: &ShaExtendCols<AB::Var> = main.row_slice(0).borrow();
    let next: &ShaExtendCols<AB::Var> = main.row_slice(1).borrow();

    let one = AB::Expr::from(AB::F::one());
    let cycle_16_generator =
        AB::F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

    // Initialize counter variables on the first row.
    builder
        .when_first_row()
        .assert_eq(local.cycle_16, cycle_16_generator);

    // Multiply the current cycle by the generator of group with order 16.
    builder
        .when_transition()
        .assert_eq(local.cycle_16 * cycle_16_generator, next.cycle_16);

    // Calculate whether 16 cycles have passed.
    builder.assert_eq(local.cycle_16 - one.clone(), local.cycle_16_minus_one);
    builder.assert_eq(
        one.clone() - local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
        local.cycle_16_minus_one_is_zero,
    );
    builder.assert_zero(local.cycle_16_minus_one * local.cycle_16_minus_one_is_zero);

    // Increment the step flags when 16 cycles have passed. Otherwise, keep them the same.
    for i in 0..3 {
        builder
            .when_transition()
            .when(local.cycle_16_minus_one_is_zero)
            .assert_eq(local.cycle_3[i], next.cycle_3[(i + 1) % 3]);
        builder
            .when_transition()
            .when(one.clone() - local.cycle_16_minus_one_is_zero)
            .assert_eq(local.cycle_3[i], next.cycle_3[i]);
    }

    // Increment `i` by one. Once it reaches the end of the cycle, reset it to zero.
    builder
        .when_transition()
        .when(local.cycle_16_minus_one_is_zero * local.cycle_3[2])
        .assert_eq(next.i, AB::F::zero());
    builder
        .when_transition()
        .when(one.clone() - local.cycle_16_minus_one_is_zero)
        .assert_eq(local.i + one.clone(), next.i);

    builder.assert_eq(
        local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
        local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
    );
}
