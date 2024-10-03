use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::syscalls::SyscallCode;
use sp1_stark::air::{InteractionScope, SP1AirBuilder};

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{
        Add4Operation, FixedRotateRightOperation, FixedShiftRightOperation, XorOperation,
    },
};

use core::borrow::Borrow;
use sp1_stark::air::BaseAirBuilder;

impl<F> BaseAir<F> for ShaExtendChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<AB> Air<AB> for ShaExtendChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ShaExtendCols<AB::Var> = (*local).borrow();
        let next: &ShaExtendCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let i_start = AB::F::from_canonical_u32(16);
        let nb_bytes_in_word = AB::F::from_canonical_u32(4);

        // Evaluate the control flags.
        self.eval_flags(builder);

        // Copy over the inputs until the result has been computed (every 48 rows).
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.shard, next.shard);
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.clk, next.clk);
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.w_ptr, next.w_ptr);

        // Read w[i-15].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(15)) * nb_bytes_in_word,
            &local.w_i_minus_15,
            local.is_real,
        );

        // Read w[i-2].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(2)) * nb_bytes_in_word,
            &local.w_i_minus_2,
            local.is_real,
        );

        // Read w[i-16].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(16)) * nb_bytes_in_word,
            &local.w_i_minus_16,
            local.is_real,
        );

        // Read w[i-7].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_canonical_u32(7)) * nb_bytes_in_word,
            &local.w_i_minus_7,
            local.is_real,
        );

        // Compute `s0`.
        // w[i-15] rightrotate 7.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            7,
            local.w_i_minus_15_rr_7,
            local.is_real,
        );
        // w[i-15] rightrotate 18.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            18,
            local.w_i_minus_15_rr_18,
            local.is_real,
        );
        // w[i-15] rightshift 3.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            3,
            local.w_i_minus_15_rs_3,
            local.is_real,
        );
        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15_rr_7.value,
            local.w_i_minus_15_rr_18.value,
            local.s0_intermediate,
            local.is_real,
        );
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.w_i_minus_15_rs_3.value,
            local.s0,
            local.is_real,
        );

        // Compute `s1`.
        // w[i-2] rightrotate 17.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            17,
            local.w_i_minus_2_rr_17,
            local.is_real,
        );
        // w[i-2] rightrotate 19.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            19,
            local.w_i_minus_2_rr_19,
            local.is_real,
        );
        // w[i-2] rightshift 10.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            10,
            local.w_i_minus_2_rs_10,
            local.is_real,
        );
        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2_rr_17.value,
            local.w_i_minus_2_rr_19.value,
            local.s1_intermediate,
            local.is_real,
        );
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.w_i_minus_2_rs_10.value,
            local.s1,
            local.is_real,
        );

        // s2 := w[i-16] + s0 + w[i-7] + s1.
        Add4Operation::<AB::F>::eval(
            builder,
            *local.w_i_minus_16.value(),
            local.s0.value,
            *local.w_i_minus_7.value(),
            local.s1.value,
            local.is_real,
            local.s2,
        );

        // Write `s2` to `w[i]`.
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + local.i * nb_bytes_in_word,
            &local.w_i,
            local.is_real,
        );

        builder.assert_word_eq(*local.w_i.value(), local.s2.value);

        // Receive syscall event in first row of 48-cycle.
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::SHA_EXTEND.syscall_id()),
            local.w_ptr,
            AB::Expr::zero(),
            local.cycle_48_start,
            InteractionScope::Local,
        );

        // Assert that is_real is a bool.
        builder.assert_bool(local.is_real);

        // Ensure that all rows in a 48 row cycle has the same `is_real` values.
        builder
            .when_transition()
            .when_not(local.cycle_48_end)
            .assert_eq(local.is_real, next.is_real);

        // Assert that the table ends in nonreal columns. Since each extend ecall is 48 cycles and
        // the table is padded to a power of 2, the last row of the table should always be padding.
        builder.when_last_row().assert_zero(local.is_real);
    }
}
