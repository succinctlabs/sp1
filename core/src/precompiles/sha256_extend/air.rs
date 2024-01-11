use p3_air::{Air, AirBuilder, BaseAir};

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};
use crate::air::CurtaAirBuilder;
use crate::operations::{
    Add4Operation, FixedRotateRightOperation, FixedShiftRightOperation, Xor3Operation,
};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;
use std::borrow::Borrow;

impl<F> BaseAir<F> for ShaExtendChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<AB> Air<AB> for ShaExtendChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaExtendCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaExtendCols<AB::Var> = main.row_slice(1).borrow();

        // Evaluate the control flags.
        self.eval_flags(builder);

        // Copy over the inputs until the result has been computed (every 48 rows).
        builder
            .when_transition()
            .when_not(local.cycle_48_end)
            .assert_eq(local.segment, next.segment);
        builder
            .when_transition()
            .when_not(local.cycle_48_end)
            .assert_eq(local.clk, next.clk);
        builder
            .when_transition()
            .when_not(local.cycle_48_end)
            .assert_eq(local.w_ptr, next.w_ptr);

        // Read w[i-15].
        builder.constraint_memory_access(
            local.segment,
            local.clk + (local.i - AB::F::from_canonical_u64(16)) * AB::F::from_canonical_u32(20),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(15)) * AB::F::from_canonical_u32(4),
            local.w_i_minus_15,
            local.is_real,
        );

        // Read w[i-2].
        builder.constraint_memory_access(
            local.segment,
            local.clk
                + (local.i - AB::F::from_canonical_u64(16)) * AB::F::from_canonical_u32(20)
                + AB::F::from_canonical_u32(4),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(2)) * AB::F::from_canonical_u32(4),
            local.w_i_minus_2,
            AB::F::one(),
        );

        // Read w[i-16].
        builder.constraint_memory_access(
            local.segment,
            local.clk
                + (local.i - AB::F::from_canonical_u64(16)) * AB::F::from_canonical_u32(20)
                + AB::F::from_canonical_u32(8),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(16)) * AB::F::from_canonical_u32(4),
            local.w_i_minus_16,
            AB::F::one(),
        );

        // Read w[i-7].
        builder.constraint_memory_access(
            local.segment,
            local.clk
                + (local.i - AB::F::from_canonical_u64(16)) * AB::F::from_canonical_u32(20)
                + AB::F::from_canonical_u32(12),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(7)) * AB::F::from_canonical_u32(4),
            local.w_i_minus_7,
            AB::F::one(),
        );

        // Compute `s0`.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15.value,
            7,
            local.w_i_minus_15_rr_7,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15.value,
            18,
            local.w_i_minus_15_rr_18,
        );
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15.value,
            3,
            local.w_i_minus_15_rs_3,
        );
        Xor3Operation::<AB::F>::eval(
            builder,
            local.w_i_minus_15_rr_7.value,
            local.w_i_minus_15_rr_18.value,
            local.w_i_minus_15_rs_3.value,
            local.s0,
        );

        // Compute `s1`.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2.value,
            17,
            local.w_i_minus_2_rr_17,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2.value,
            19,
            local.w_i_minus_2_rr_19,
        );
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2.value,
            10,
            local.w_i_minus_2_rs_10,
        );
        Xor3Operation::<AB::F>::eval(
            builder,
            local.w_i_minus_2_rr_17.value,
            local.w_i_minus_2_rr_19.value,
            local.w_i_minus_2_rs_10.value,
            local.s1,
        );

        // Compute `s2`.
        Add4Operation::<AB::F>::eval(
            builder,
            local.w_i_minus_16.value,
            local.s0.value,
            local.w_i_minus_7.value,
            local.s1.value,
            local.s2,
        );

        // Write `s2` to `w[i]`.
        builder.constraint_memory_access(
            local.segment,
            local.clk
                + (local.i - AB::F::from_canonical_u64(16)) * AB::F::from_canonical_u32(20)
                + AB::F::from_canonical_u32(16),
            local.w_ptr + local.i * AB::F::from_canonical_u32(4),
            local.w_i,
            AB::F::one(),
        );
    }
}
