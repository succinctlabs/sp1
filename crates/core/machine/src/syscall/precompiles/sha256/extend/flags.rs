use core::borrow::Borrow;
use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32, TwoAdicField};
use p3_matrix::Matrix;
use sp1_stark::air::{BaseAirBuilder, SP1AirBuilder};

use crate::operations::IsZeroOperation;

use super::{ShaExtendChip, ShaExtendCols};

impl<F: Field> ShaExtendCols<F> {
    pub fn populate_flags(&mut self, i: usize) {
        // The generator of the multiplicative subgroup.
        let g = F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

        // Populate the columns needed to keep track of cycles of 16 rows.
        self.cycle_16 = g.exp_u64((i + 1) as u64);

        // Populate the columns needed to track the start of a cycle of 16 rows.
        self.cycle_16_start.populate_from_field_element(self.cycle_16 - g);

        // Populate the columns needed to track the end of a cycle of 16 rows.
        self.cycle_16_end.populate_from_field_element(self.cycle_16 - F::one());

        // Populate the columns needed to keep track of cycles of 48 rows.
        let j = 16 + (i % 48);
        self.i = F::from_canonical_usize(j);
        self.cycle_48[0] = F::from_bool((16..32).contains(&j));
        self.cycle_48[1] = F::from_bool((32..48).contains(&j));
        self.cycle_48[2] = F::from_bool((48..64).contains(&j));
        self.cycle_48_start = self.cycle_48[0] * self.cycle_16_start.result * self.is_real;
        self.cycle_48_end = self.cycle_48[2] * self.cycle_16_end.result * self.is_real;
    }
}

impl ShaExtendChip {
    pub fn eval_flags<AB: SP1AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ShaExtendCols<AB::Var> = (*local).borrow();
        let next: &ShaExtendCols<AB::Var> = (*next).borrow();

        let one = AB::Expr::from(AB::F::one());

        // Generator with order 16 within BabyBear.
        let g = AB::F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

        // First row of the table must have g^1.
        builder.when_first_row().assert_eq(local.cycle_16, g);

        // First row of the table must have i = 16.
        builder.when_first_row().assert_eq(local.i, AB::F::from_canonical_u32(16));

        // Every row's `cycle_16` must be previous multiplied by `g`.
        builder.when_transition().assert_eq(local.cycle_16 * g, next.cycle_16);

        // Constrain `cycle_16_start.result` to be `cycle_16 - g == 0`.
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.cycle_16 - AB::Expr::from(g),
            local.cycle_16_start,
            one.clone(),
        );

        // Constrain `cycle_16_end.result` to be `cycle_16 - 1 == 0`. Intuitively g^16 is 1.
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.cycle_16 - AB::Expr::one(),
            local.cycle_16_end,
            one.clone(),
        );

        // Constrain `cycle_48` to be [1, 0, 0] in the first row.
        builder.when_first_row().assert_eq(local.cycle_48[0], AB::F::one());
        builder.when_first_row().assert_eq(local.cycle_48[1], AB::F::zero());
        builder.when_first_row().assert_eq(local.cycle_48[2], AB::F::zero());

        // Shift the indices of `cycles_48` at the end of each 16 rows. Otherwise, keep them the
        // same.
        for i in 0..3 {
            builder
                .when_transition()
                .when(local.cycle_16_end.result)
                .assert_eq(local.cycle_48[i], next.cycle_48[(i + 1) % 3]);
            builder
                .when_transition()
                .when(one.clone() - local.cycle_16_end.result)
                .assert_eq(local.cycle_48[i], next.cycle_48[i]);
            builder.assert_bool(local.cycle_48[i]);
        }

        // cycle_48_start == start of 16-cycle AND first 16-cycle within 48-cycle AND is_real.
        builder.assert_eq(
            local.cycle_16_start.result * local.cycle_48[0] * local.is_real,
            local.cycle_48_start,
        );

        // cycle_48_end == end of 16-cycle AND last 16-cycle within 48-cycle AND is_real.
        builder.assert_eq(
            local.cycle_16_end.result * local.cycle_48[2] * local.is_real,
            local.cycle_48_end,
        );

        // When it's the end of a 48-cycle, the next `i` must be 16.
        builder
            .when_transition()
            .when(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(next.i, AB::F::from_canonical_u32(16));

        // When it's not the end of a 48-cycle, the next `i` must be the current plus one.
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.i + one.clone(), next.i);
    }
}
