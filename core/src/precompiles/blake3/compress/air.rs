use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};

use super::columns::{Blake3CompressInnerCols, NUM_BLAKE3_COMPRESS_INNER_COLS};
use super::{
    Blake3CompressInnerChip, MIX_OPERATION_INDEX, MIX_OPERATION_INPUT_SIZE, NUM_MSG_WORDS_PER_CALL,
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

        self.constraint_external_ops(builder, local);
    }
}

impl Blake3CompressInnerChip {
    fn constrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
        next: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // let index_to_read = {
        //     let acc = AB::Expr::from_canonical_usize(0);
        //     for round in 0..ROUND_COUNT {
        //         for operation in 0..OPERATION_COUNT {
        //             acc += AB::Expr::from_canonical_usize(MIX_OPERATION_INDEX[operation][i])
        //                 * local.is_operation_index_n[operation]
        //                 * local.is_round_index_n[round];
        //         }
        //     }
        // };
        // // If this is the i-th round, then the next row should be the (i+1)-th round.
        // for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //     builder.when_transition().when(next.is_real).assert_eq(
        //         local.is_round_n[i],
        //         next.is_round_n[(i + 1) % P2_EXTERNAL_ROUND_COUNT],
        //     );
        //     builder.assert_bool(local.is_round_n[i]);
        // }

        // // Exactly one of the is_round_n flags is set.
        // {
        //     let sum_is_round_n = {
        //         let mut acc: AB::Expr = AB::F::zero().into();
        //         for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //             acc += local.is_round_n[i].into();
        //         }
        //         acc
        //     };

        //     builder
        //         .when(local.is_real)
        //         .assert_eq(sum_is_round_n, AB::F::from_canonical_usize(1));
        // }

        // // Calculate the current round number.
        // {
        //     let round = {
        //         let mut acc: AB::Expr = AB::F::zero().into();

        //         for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //             acc += local.is_round_n[i] * AB::F::from_canonical_usize(i);
        //         }
        //         acc
        //     };
        //     builder.assert_eq(round, local.round_number);
        // }

        // // Calculate the round constants for this round.
        // {
        //     for i in 0..P2_WIDTH {
        //         let round_constant = {
        //             let mut acc: AB::Expr = AB::F::zero().into();

        //             for j in 0..P2_EXTERNAL_ROUND_COUNT {
        //                 acc += local.is_round_n[j].into()
        //                     * AB::F::from_wrapped_u32(P2_ROUND_CONSTANTS[j][i]);
        //             }
        //             acc
        //         };
        //         builder.assert_eq(round_constant, local.round_constant[i]);
        //     }
        // }
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // let mut state = [0u32; STATE_SIZE];
        // for i in 0..NUM_STATE_WORDS_PER_CALL {
        //     let index_to_read = MIX_OPERATION_INDEX[operation][i];
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
        //     let index_to_write = MIX_OPERATION_INDEX[operation][i];
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

    fn constraint_external_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // // Convert each Word into one field element. MemoryRead returns an array of Words, but we
        // // need to perform operations within the field.
        // let input_state = local.mem_reads.map(|read| {
        //     let mut acc: AB::Expr = AB::F::zero().into();
        //     for i in 0..WORD_SIZE {
        //         let shift: AB::Expr = AB::F::from_canonical_usize(1 << (8 * i)).into();
        //         acc += read.access.value[i].into() * shift;
        //     }
        //     acc
        // });

        // builder.assert_bool(local.is_real);

        // AddRcOperation::<AB::F>::eval(
        //     builder,
        //     input_state,
        //     local.is_round_n,
        //     local.round_constant,
        //     local.add_rc,
        //     local.is_real,
        // );

        // SBoxOperation::<AB::F>::eval(builder, local.add_rc.result, local.sbox, local.is_real);

        // ExternalLinearPermuteOperation::<AB::F>::eval(
        //     builder,
        //     local.sbox.acc.map(|x| *x.last().unwrap()),
        //     local.external_linear_permute,
        //     local.is_real,
        // );
    }
}
