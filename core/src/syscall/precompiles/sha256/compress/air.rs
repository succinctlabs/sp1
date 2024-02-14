use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;

use super::ch::ChOperation;
use super::columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS};
use super::maj::MajOperation;
use super::s0::S0Operation;
use super::s1::S1Operation;
use super::ShaCompressChip;
use crate::air::{BaseAirBuilder, SP1AirBuilder, Word, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::AddOperation;
use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

impl<F> BaseAir<F> for ShaCompressChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for ShaCompressChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaCompressCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaCompressCols<AB::Var> = main.row_slice(1).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constrain_compression_ops(builder, local);

        self.constrain_finalize_ops(builder, local);
    }
}

impl ShaCompressChip {
    fn constrain_control_flow_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
        next: &ShaCompressCols<AB::Var>,
    ) {
        // Constrain octet columns.

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

        // Constrain octet_num columns

        // Verify that all of the octet_num columns are bool.
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

    fn constrain_memory<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let is_initialize = local.octet_num[0];
        let is_finalize = local.octet_num[9];
        builder.constraint_memory_access(
            local.shard,
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

    fn constrain_compression_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        // Calculate S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25).
        let _s1 = {
            S1Operation::<AB::F>::eval(builder, local.e, local.s1, local.is_compression);
            local.s1.s1.value
        };

        // Calculate ch := (e and f) xor ((not e) and g).
        let _ch = {
            ChOperation::<AB::F>::eval(
                builder,
                local.e,
                local.f,
                local.g,
                local.ch,
                local.is_compression,
            );
            local.ch.ch.value
        };

        // Calculate S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22).
        let s0 = {
            S0Operation::<AB::F>::eval(builder, local.a, local.s0, local.is_compression);
            local.s0.s0.value
        };

        // TODO: We need to constrain temp1.

        // Calculate maj := (a and b) xor (a and c) xor (b and c).
        let maj = {
            MajOperation::<AB::F>::eval(
                builder,
                local.a,
                local.b,
                local.c,
                local.maj,
                local.is_compression,
            );
            local.maj.maj.value
        };

        // Calculate temp2 := S0 + maj.
        let temp2 = {
            AddOperation::<AB::F>::eval(builder, s0, maj, local.temp2, local.is_compression);
            local.temp2.value
        };

        // Calculate d + temp1 for the new value of e.
        AddOperation::<AB::F>::eval(
            builder,
            local.d,
            local.temp1.value,
            local.d_add_temp1,
            local.is_compression,
        );

        // Calculate temp1 + temp2 for the new value of a.
        AddOperation::<AB::F>::eval(
            builder,
            local.temp1.value,
            temp2,
            local.temp1_add_temp2,
            local.is_compression,
        );
    }

    fn constrain_finalize_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let is_finalize = local.octet_num[9];
        // In the finalize phase, need to execute h[0] + a, h[1] + b, ..., h[7] + h, for each of the
        // phase's 8 rows.
        // We can get the needed operand (a,b,c,...,h) by doing an inner product between octet and
        // [a,b,c,...,h] which will act as a selector.
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
            .assert_word_eq(*local.mem.value(), local.finalize_add.value);
    }
}
