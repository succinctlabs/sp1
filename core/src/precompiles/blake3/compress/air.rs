use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};

use super::columns::{Blake3CompressInnerCols, NUM_BLAKE3_COMPRESS_INNER_COLS};
use super::g::GOperation;
use super::{
    Blake3CompressInnerChip, G_INDEX, G_INPUT_SIZE, MSG_SCHEDULE, NUM_MSG_WORDS_PER_CALL,
    NUM_STATE_WORDS_PER_CALL, OPERATION_COUNT, ROUND_COUNT, STATE_SIZE,
};
use crate::air::{CurtaAirBuilder, WORD_SIZE};

use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

impl<F> BaseAir<F> for Blake3CompressInnerChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COMPRESS_INNER_COLS
    }
}

impl<AB> Air<AB> for Blake3CompressInnerChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake3CompressInnerCols<AB::Var> = main.row_slice(0).borrow();
        let next: &Blake3CompressInnerCols<AB::Var> = main.row_slice(1).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constraint_compress_ops(builder, local);
    }
}

impl Blake3CompressInnerChip {
    fn constrain_index_selector<AB: CurtaAirBuilder>(
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

    fn constrain_control_flow_flags<AB: CurtaAirBuilder>(
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
                    .assert_eq(
                        local.round_index + AB::F::from_canonical_u16(1),
                        next.round_index,
                    );
            }
        }
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // let mut state = [0u32; STATE_SIZE];
        // for i in 0..NUM_STATE_WORDS_PER_CALL {
        //     let index_to_read = G_INDEX[operation][i];
        //     let (record, value) = rt.mr(state_ptr + (index_to_read as u32) * 4);
        //     read_records[round][operation][i] = record;
        //     state[index_to_read] = value;
        //     rt.clk += 4;
        // }
        let clk_cycle_per_word: AB::Expr = AB::F::from_canonical_usize(4).into();
        let mut clk: AB::Expr = local.clk.into();
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            builder.constraint_memory_access(
                local.segment,
                clk.clone(),
                local.state_ptr + local.state_index[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.mem_reads[i],
                local.is_real,
            );
            clk += clk_cycle_per_word.clone();
        }
        // // Read the message.
        // let mut message = [0u32; MSG_SIZE];
        // for i in 0..NUM_MSG_WORDS_PER_CALL {
        //     let index_to_read = MSG_SCHEDULE[round][2 * operation + i];
        //     let (record, value) = rt.mr(msg_ptr + (index_to_read as u32) * 4);
        //     read_records[round][operation][NUM_STATE_WORDS_PER_CALL + i] = record;
        //     message[index_to_read] = value;
        //     rt.clk += 4;
        // }

        let msg_ptr = local.state_ptr + AB::F::from_canonical_usize(4 * STATE_SIZE);
        for i in 0..NUM_MSG_WORDS_PER_CALL {
            builder.constraint_memory_access(
                local.segment,
                clk.clone(),
                msg_ptr.clone() + local.msg_schedule[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.mem_reads[NUM_STATE_WORDS_PER_CALL + i],
                local.is_real,
            );
            clk += clk_cycle_per_word.clone();
        }

        // // Write the state.
        // for i in 0..NUM_STATE_WORDS_PER_CALL {
        //     let index_to_write = G_INDEX[operation][i];
        //     let record = rt.mw(
        //         state_ptr.wrapping_add((index_to_write as u32) * 4),
        //         results[index_to_write],
        //     );
        //     write_records[round][operation][i] = record;
        //     rt.clk += 4;
        // }
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            builder.constraint_memory_access(
                local.segment,
                clk.clone(),
                local.state_ptr + local.state_index[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.mem_writes[i],
                local.is_real,
            );
            clk += clk_cycle_per_word.clone();
        }
    }

    fn constraint_compress_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);
        // Calculate the 4 indices to read from the state. This corresponds to a, b, c, and d.
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            let index_to_read = {
                self.constrain_index_selector(
                    builder,
                    &local.is_operation_index_n,
                    local.operation_index,
                    local.is_real,
                );

                self.constrain_index_selector(
                    builder,
                    &local.is_round_index_n,
                    local.round_index,
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

        // Calculate the MSG_SCHEDULE index to read from the message.
        for i in 0..NUM_MSG_WORDS_PER_CALL {
            let index_to_read = {
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

        // Call the g function.
        GOperation::<AB::F>::eval(
            builder,
            local.mem_reads.map(|x| x.access.value),
            local.g,
            local.is_real,
        );

        // Finally, the results of the g function should be written to the memory.

        for i in 0..NUM_STATE_WORDS_PER_CALL {
            for j in 0..WORD_SIZE {
                builder
                    .when(local.is_real)
                    .assert_eq(local.mem_writes[i].access.value[j], local.g.result[i][j]);
            }
        }
    }
}
