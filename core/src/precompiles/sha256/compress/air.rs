use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;

use super::columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS};
use super::ShaCompressChip;
use crate::air::{BaseAirBuilder, CurtaAirBuilder, Word, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::{
    AddOperation, AndOperation, FixedRotateRightOperation, NotOperation, XorOperation,
};
use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

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

        self.constrain_compression_ops(builder, local);

        self.constrain_finalize_ops(builder, local);
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
        builder.when(local.is_real).assert_one(octet_sum);

        // Verify that the first row's octet value is correct.
        builder
            .when_first_row()
            .when(local.is_real)
            .assert_one(local.octet[0]);

        // Verify correct transition for octet column.
        for i in 0..8 {
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.octet[i])
                .assert_one(next.octet[(i + 1) % 8])
        }

        //// Constrain octet_num columns
        // Verify taht all of the octet_num columns are bool.
        for i in 0..10 {
            builder.assert_bool(local.octet_num[i]);
        }

        // Verify that exactly one of the octet_num columns is true.
        let mut octet_num_sum = AB::Expr::zero();
        for i in 0..10 {
            octet_num_sum += local.octet_num[i].into();
        }
        builder.when(local.is_real).assert_one(octet_num_sum);

        // Verify that the first row's octet_num value is correct.
        builder
            .when_first_row()
            .when(local.is_real)
            .assert_one(local.octet_num[0]);

        for i in 0..10 {
            builder
                .when_transition()
                .when(next.is_real)
                .when_not(local.octet[7])
                .assert_eq(local.octet_num[i], next.octet_num[i]);
        }

        for i in 0..10 {
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.octet[7])
                .assert_eq(local.octet_num[i], next.octet_num[(i + 1) % 10]);
        }

        // Assert that the is_compression flag is correct.
        builder.assert_eq(
            local.is_compression,
            local.octet_num[1]
                + local.octet_num[2]
                + local.octet_num[3]
                + local.octet_num[4]
                + local.octet_num[5]
                + local.octet_num[6]
                + local.octet_num[7]
                + local.octet_num[8],
        );
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let is_initialize = local.octet_num[0];
        let is_finalize = local.octet_num[9];
        builder.constraint_memory_access(
            local.segment,
            local.clk,
            local.mem_addr,
            &local.mem,
            is_initialize + local.is_compression + is_finalize,
        );

        // Calculate the current cycle_num.
        let mut cycle_num = AB::Expr::zero();
        for i in 0..10 {
            cycle_num += local.octet_num[i] * AB::Expr::from_canonical_usize(i);
        }

        // Calculate the current step of the cycle 8.
        let mut cycle_step = AB::Expr::zero();
        for i in 0..8 {
            cycle_step += local.octet[i] * AB::Expr::from_canonical_usize(i);
        }

        // Verify correct mem address for initialize phase
        builder.when(is_initialize).assert_eq(
            local.mem_addr,
            local.w_and_h_ptr
                + (AB::Expr::from_canonical_u32(64 * 4)
                    + cycle_step.clone() * AB::Expr::from_canonical_u32(4)),
        );

        // Verify correct mem address for compression phase
        builder.when(local.is_compression).assert_eq(
            local.mem_addr,
            local.w_and_h_ptr
                + (((cycle_num - AB::Expr::one()) * AB::Expr::from_canonical_u32(8))
                    + cycle_step.clone())
                    * AB::Expr::from_canonical_u32(4),
        );

        // Verify correct mem address for finalize phase
        builder.when(is_finalize).assert_eq(
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
                .when(is_initialize)
                .when(local.octet[i])
                .assert_word_eq(vars[i], *local.mem.value());
        }
    }

    fn constrain_compression_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
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
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.e_rr_25.value,
            local.s1,
            local.is_compression,
        );

        AndOperation::<AB::F>::eval(
            builder,
            local.e,
            local.f,
            local.e_and_f,
            local.is_compression,
        );
        NotOperation::<AB::F>::eval(builder, local.e, local.e_not, local.is_compression);
        AndOperation::<AB::F>::eval(
            builder,
            local.e_not.value,
            local.g,
            local.e_not_and_g,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.e_and_f.value,
            local.e_not_and_g.value,
            local.ch,
            local.is_compression,
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
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.a_rr_22.value,
            local.s0,
            local.is_compression,
        );

        AndOperation::<AB::F>::eval(
            builder,
            local.a,
            local.b,
            local.a_and_b,
            local.is_compression,
        );
        AndOperation::<AB::F>::eval(
            builder,
            local.a,
            local.c,
            local.a_and_c,
            local.is_compression,
        );
        AndOperation::<AB::F>::eval(
            builder,
            local.b,
            local.c,
            local.b_and_c,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.a_and_b.value,
            local.a_and_c.value,
            local.maj_intermediate,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.maj_intermediate.value,
            local.b_and_c.value,
            local.maj,
            local.is_compression,
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

    fn constrain_finalize_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let is_finalize = local.octet_num[9];
        // In the finalize phase, need to execute h[0] + a, h[1] + b, ..., h[7] + h, for each of the
        // phase's 8 rows.
        // We can get the needed operand (a,b,c,...,h) by doing an inner product between octet and [a,b,c,...,h]
        // which will act as a selector.
        let add_operands = [
            local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h,
        ];
        let zero = AB::Expr::zero();
        let mut filtered_operand = Word([zero.clone(), zero.clone(), zero.clone(), zero]);
        for (i, operand) in local.octet.iter().zip(add_operands.iter()) {
            for j in 0..4 {
                filtered_operand.0[j] += *i * operand.0[j];
            }
        }

        builder
            .when(is_finalize)
            .assert_word_eq(filtered_operand, local.finalized_operand.map(|x| x.into()));

        AddOperation::<AB::F>::eval(
            builder,
            local.mem.prev_value,
            local.finalized_operand,
            local.finalize_add,
            is_finalize,
        );

        builder
            .when(is_finalize)
            .assert_word_eq(*local.mem.value(), local.finalize_add.value);
    }
}
