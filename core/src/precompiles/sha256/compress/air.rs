use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;

use super::columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS};
use super::ShaCompressChip;
use crate::air::{BaseAirBuilder, CurtaAirBuilder, WordAirBuilder};
use crate::operations::{
    AddOperation, AndOperation, FixedRotateRightOperation, NotOperation, XorOperation,
};
use p3_matrix::MatrixRowSlices;
use std::borrow::Borrow;

impl<F> BaseAir<F> for ShaCompressChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for ShaCompressChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaCompressCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaCompressCols<AB::Var> = main.row_slice(1).borrow();

        self.contrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        builder.constraint_memory_access(
            local.segment,
            local.clk,
            local.mem_addr,
            local.mem,
            local.is_initialize + local.is_compression + local.is_finalize,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            6,
            local.e_rr_6,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            11,
            local.e_rr_11,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            25,
            local.e_rr_25,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.e_rr_6.value,
            local.e_rr_11.value,
            local.s1_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.e_rr_25.value,
            local.s1,
        );

        AndOperation::<AB::F>::eval(builder, local.e, local.f, local.e_and_f);
        NotOperation::<AB::F>::eval(builder, local.e, local.e_not);
        AndOperation::<AB::F>::eval(builder, local.e_not.value, local.g, local.e_not_and_g);
        XorOperation::<AB::F>::eval(
            builder,
            local.e_and_f.value,
            local.e_not_and_g.value,
            local.ch,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            2,
            local.a_rr_2,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            13,
            local.a_rr_13,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            22,
            local.a_rr_22,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.a_rr_2.value,
            local.a_rr_13.value,
            local.s0_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.a_rr_22.value,
            local.s0,
        );

        AndOperation::<AB::F>::eval(builder, local.a, local.b, local.a_and_b);
        AndOperation::<AB::F>::eval(builder, local.a, local.c, local.a_and_c);
        AndOperation::<AB::F>::eval(builder, local.b, local.c, local.b_and_c);
        XorOperation::<AB::F>::eval(
            builder,
            local.a_and_b.value,
            local.a_and_c.value,
            local.maj_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.maj_intermediate.value,
            local.b_and_c.value,
            local.maj,
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.s0.value,
            local.maj.value,
            local.temp2,
            local.is_compression,
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.d,
            local.temp1.value,
            local.d_add_temp1,
            local.is_compression,
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.temp1.value,
            local.temp2.value,
            local.temp1_add_temp2,
            local.is_compression,
        );
    }
}

impl ShaCompressChip {
    fn contrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
        next: &ShaCompressCols<AB::Var>,
    ) {
        //// Constrain octet columns
        // Verify that all of the octet columns are bool.
        for i in 0..8 {
            builder.assert_bool(local.octet[i]);
        }
        // Verify that exactly one of the octet columns is true.
        let mut octet_sum = AB::Expr::zero();
        for i in 0..8 {
            octet_sum += local.octet[i].into();
        }
        builder.assert_one(octet_sum);

        // Verify that the first row's octet value is correct.
        builder.when_first_row().assert_one(local.octet[0]);

        // Verify correct transition for octet column.
        for i in 0..7 {
            builder
                .when_transition()
                .when(local.octet[i])
                .assert_one(next.octet[i + 1])
        }
        builder
            .when_transition()
            .when(local.octet[7])
            .assert_one(next.octet[0]);

        //// Constrain octet_num columns
        // Verify taht all of the octet_num columns are bool.
        for i in 0..8 {
            builder.assert_bool(local.octet_num[i]);
        }

        // Verify that exactly one of the octet_num columns is true.
        let mut octet_num_sum = AB::Expr::zero();
        for i in 0..8 {
            octet_num_sum += local.octet_num[i].into();
        }
        builder.assert_one(octet_num_sum);

        // Verify that the first row's octet_num value is correct.
        builder.when_first_row().assert_one(local.octet_num[0]);

        for i in 0..8 {
            builder
                .when_transition()
                .when_not(local.octet[7])
                .assert_eq(local.octet_num[i], next.octet_num[i]);
        }

        for i in 0..8 {
            builder
                .when_transition()
                .when(local.octet[7])
                .assert_eq(local.octet_num[i], next.octet_num[(i + 1) % 8]);
        }

        builder.assert_eq(local.is_initialize, local.octet_num[0]);
        builder.assert_eq(
            local.is_compression,
            local.octet_num[1]
                + local.octet_num[2]
                + local.octet_num[3]
                + local.octet_num[4]
                + local.octet_num[5]
                + local.octet_num[6],
        );
        builder.assert_eq(local.is_finalize, local.octet_num[7]);
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let mut cycle_step = AB::Expr::zero();
        for i in 0..8 {
            cycle_step += local.octet[i] * AB::Expr::from_canonical_usize(i);
        }

        // Verify correct mem address for initialize phase
        builder.when(local.is_initialize).assert_eq(
            local.mem_addr,
            local.w_and_h_ptr
                + (AB::Expr::from_canonical_u32(64 * 4)
                    + cycle_step.clone() * AB::Expr::from_canonical_u32(4)),
        );

        // Verify correct mem address for compression phase
        builder.when(local.is_compression).assert_eq(
            local.mem_addr,
            local.w_and_h_ptr + cycle_step.clone() * AB::Expr::from_canonical_u32(4),
        );

        // Verify correct mem address for finalize phase
        builder.when(local.is_finalize).assert_eq(
            local.mem_addr,
            local.w_and_h_ptr
                + (AB::Expr::from_canonical_u32(64 * 4)
                    + cycle_step.clone() * AB::Expr::from_canonical_u32(4)),
        );

        // In the initialize phase, verify that local.a, local.b, ... is correctly set to the
        // memory value.
        let vars = [
            local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h,
        ];
        for i in 0..8 {
            builder
                .when(local.is_initialize)
                .when(local.octet[i])
                .assert_word_eq(vars[i], local.mem.value);
        }
    }
}
