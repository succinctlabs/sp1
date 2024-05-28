use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use super::columns::{Blake3CompressInnerCols, NUM_BLAKE3_COMPRESS_INNER_COLS};
use super::g::GOperation;
use super::{
    Blake3CompressInnerChip, G_INDEX, MSG_SCHEDULE, NUM_MSG_WORDS_PER_CALL,
    NUM_STATE_WORDS_PER_CALL, OPERATION_COUNT, ROUND_COUNT,
};
use crate::air::{BaseAirBuilder, SP1AirBuilder, WORD_SIZE};
use crate::runtime::SyscallCode;

impl<F> BaseAir<F> for Blake3CompressInnerChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COMPRESS_INNER_COLS
    }
}

impl<AB> Air<AB> for Blake3CompressInnerChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Blake3CompressInnerCols<AB::Var> = (*local).borrow();
        let next: &Blake3CompressInnerCols<AB::Var> = (*next).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constrain_g_operation(builder, local);

        // TODO: constraint ecall_receive column.
        // TODO: constraint clk column to increment by 1 within same invocation of syscall.
        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::BLAKE3_COMPRESS_INNER.syscall_id()),
            local.state_ptr,
            local.message_ptr,
            local.ecall_receive,
        );
    }
}

impl Blake3CompressInnerChip {
    /// Constrains the given index is correct for the given selector. The `selector` is an
    /// `n`-dimensional boolean array whose `i`-th element is true if and only if the index is `i`.
    fn constrain_index_selector<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        selector: &[AB::Var],
        index: AB::Var,
        is_real: AB::Var,
    ) {
        let mut acc: AB::Expr = AB::F::zero().into();
        for i in 0..selector.len() {
            acc += selector[i].into();
            builder.assert_bool(selector[i])
        }
        builder
            .when(is_real)
            .assert_eq(acc, AB::F::from_canonical_usize(1));
        for i in 0..selector.len() {
            builder
                .when(selector[i])
                .assert_eq(index, AB::F::from_canonical_usize(i));
        }
    }

    /// Constrains the control flow flags such as the operation index and the round index.
    fn constrain_control_flow_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
        next: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // If this is the i-th operation, then the next row should be the (i+1)-th operation.
        for i in 0..OPERATION_COUNT {
            builder.when_transition().when(next.is_real).assert_eq(
                local.is_operation_index_n[i],
                next.is_operation_index_n[(i + 1) % OPERATION_COUNT],
            );
        }

        // If this is the last operation, the round index should be incremented. Otherwise, the
        // round index should remain the same.
        for i in 0..OPERATION_COUNT {
            if i + 1 < OPERATION_COUNT {
                builder
                    .when_transition()
                    .when(local.is_operation_index_n[i])
                    .assert_eq(local.round_index, next.round_index);
            } else {
                builder
                    .when_transition()
                    .when(local.is_operation_index_n[i])
                    .when_not(local.is_round_index_n[ROUND_COUNT - 1])
                    .assert_eq(
                        local.round_index + AB::F::from_canonical_u16(1),
                        next.round_index,
                    );

                builder
                    .when_transition()
                    .when(local.is_operation_index_n[i])
                    .when(local.is_round_index_n[ROUND_COUNT - 1])
                    .assert_zero(next.round_index);
            }
        }
    }

    /// Constrain the memory access for the state and the message.
    fn constrain_memory<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // Calculate the 4 indices to read from the state. This corresponds to a, b, c, and d.
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            let index_to_read = {
                self.constrain_index_selector(
                    builder,
                    &local.is_operation_index_n,
                    local.operation_index,
                    local.is_real,
                );

                let mut acc = AB::Expr::from_canonical_usize(0);
                for operation in 0..OPERATION_COUNT {
                    acc += AB::Expr::from_canonical_usize(G_INDEX[operation][i])
                        * local.is_operation_index_n[operation];
                }
                acc
            };
            builder.assert_eq(local.state_index[i], index_to_read);
        }

        // Read & write the state.
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.state_ptr + local.state_index[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.state_reads_writes[i],
                local.is_real,
            );
        }

        // Calculate the indices to read from the message.
        for i in 0..NUM_MSG_WORDS_PER_CALL {
            let index_to_read = {
                self.constrain_index_selector(
                    builder,
                    &local.is_round_index_n,
                    local.round_index,
                    local.is_real,
                );

                let mut acc = AB::Expr::from_canonical_usize(0);

                for round in 0..ROUND_COUNT {
                    for operation in 0..OPERATION_COUNT {
                        acc +=
                            AB::Expr::from_canonical_usize(MSG_SCHEDULE[round][2 * operation + i])
                                * local.is_operation_index_n[operation]
                                * local.is_round_index_n[round];
                    }
                }
                acc
            };
            builder.assert_eq(local.msg_schedule[i], index_to_read);
        }

        // Read the message.
        for i in 0..NUM_MSG_WORDS_PER_CALL {
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.message_ptr + local.msg_schedule[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.message_reads[i],
                local.is_real,
            );
        }
    }

    /// Constrains the input and the output of the `g` operation.
    fn constrain_g_operation<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);

        // Call g and write the result to the state.
        {
            let input = [
                local.state_reads_writes[0].prev_value,
                local.state_reads_writes[1].prev_value,
                local.state_reads_writes[2].prev_value,
                local.state_reads_writes[3].prev_value,
                local.message_reads[0].access.value,
                local.message_reads[1].access.value,
            ];

            // Call the g function.
            GOperation::<AB::F>::eval(
                builder,
                input,
                local.g,
                local.shard,
                local.channel,
                local.is_real,
            );

            // Finally, the results of the g function should be written to the memory.
            for i in 0..NUM_STATE_WORDS_PER_CALL {
                for j in 0..WORD_SIZE {
                    builder.when(local.is_real).assert_eq(
                        local.state_reads_writes[i].access.value[j],
                        local.g.result[i][j],
                    );
                }
            }
        }
    }
}
