use core::borrow::Borrow;
use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;

use p3_matrix::MatrixRowSlices;

use crate::air::CurtaAirBuilder;

use super::ShaExtendChip;
use super::ShaExtendCols;

impl<F: Field> ShaExtendCols<F> {
    pub fn populate_flags(&mut self, i: usize) {
        // The generator of the multiplicative subgroup.
        let g = F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

        // Populate the columns needed to keep track of cycles of 16 rows.
        self.cycle_16 = g.exp_u64((i + 1) as u64);

        // Populate the columns needed to track the start of a cycle of 16 rows.
        self.cycle_16_minus_g = self.cycle_16 - g;
        self.cycle_16_minus_g_inv = self
            .cycle_16_minus_g
            .try_inverse()
            .unwrap_or_else(|| F::zero());
        self.cycle_16_start = F::from_bool(self.cycle_16_minus_g == F::zero());

        // Populate the columns needed to track the end of a cycle of 16 rows.
        self.cycle_16_minus_one = self.cycle_16 - F::one();
        self.cycle_16_minus_one_inv = self
            .cycle_16_minus_one
            .try_inverse()
            .unwrap_or_else(|| F::zero());
        self.cycle_16_end = F::from_bool(self.cycle_16_minus_one == F::zero());

        // Populate the columns needed to keep track of cycles of 48 rows.
        let j = 16 + (i % 48);
        self.i = F::from_canonical_usize(j);
        self.cycle_48[0] = F::from_bool((16..32).contains(&j));
        self.cycle_48[1] = F::from_bool((32..48).contains(&j));
        self.cycle_48[2] = F::from_bool((48..64).contains(&j));
        self.cycle_48_start = self.cycle_48[0] * self.cycle_16_start;
        self.cycle_48_end = self.cycle_48[2] * self.cycle_16_end;
    }
}

impl ShaExtendChip {
    pub fn eval_flags<AB: CurtaAirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaExtendCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaExtendCols<AB::Var> = main.row_slice(1).borrow();

        let one = AB::Expr::from(AB::F::one());
        let g = AB::F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

        // Initialize counter variables on the first row.
        builder.when_first_row().assert_eq(local.cycle_16, g);

        // Multiply the current cycle by the generator of group with order 16.
        builder
            .when_transition()
            .assert_eq(local.cycle_16 * g, next.cycle_16);

        // Calculate whether it's the beggining of the cycle of 16 rows.
        builder.assert_eq(local.cycle_16 - g, local.cycle_16_minus_g);
        builder.assert_eq(
            one.clone() - local.cycle_16_minus_g * local.cycle_16_minus_g_inv,
            local.cycle_16_start,
        );
        builder.assert_zero(local.cycle_16_minus_g * local.cycle_16_start);

        // Calculate whether it's the end of the cycle of 16 rows.
        builder.assert_eq(local.cycle_16 - one.clone(), local.cycle_16_minus_one);
        builder.assert_eq(
            one.clone() - local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
            local.cycle_16_end,
        );
        builder.assert_zero(local.cycle_16_minus_one * local.cycle_16_end);

        // Increment the indices of `cycles_48` when 16 rows have passed. Otherwise, keep them the same.
        for i in 0..3 {
            builder
                .when_transition()
                .when(local.cycle_16_end)
                .assert_eq(local.cycle_48[i], next.cycle_48[(i + 1) % 3]);
            builder
                .when_transition()
                .when(one.clone() - local.cycle_16_end)
                .assert_eq(local.cycle_48[i], next.cycle_48[i]);
        }

        // Compute whether it's the start/end of the cycle of 48 rows.
        builder.assert_eq(
            local.cycle_16_start * local.cycle_48[0],
            local.cycle_48_start,
        );
        builder.assert_eq(local.cycle_16_end * local.cycle_48[2], local.cycle_48_end);

        // Increment `i` by one. Once it reaches the end of the cycle, reset it to zero.
        builder
            .when_transition()
            .when(local.cycle_16_end * local.cycle_48[2])
            .assert_eq(next.i, AB::F::from_canonical_u32(16));
        builder
            .when_transition()
            .when(one.clone() - local.cycle_16_end)
            .assert_eq(local.i + one.clone(), next.i);

        builder.assert_eq(
            local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
            local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
        );
    }
}
