use std::borrow::Borrow;

use crate::{
    air::{SP1AirBuilder, WORD_SIZE},
    syscall::precompiles::blake2b::{MSG_ELE_PER_CALL, STATE_ELE_PER_CALL},
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;

use super::{
    columns::{Blake2bCompressInnerCols, NUM_BLAKE2B_COMPRESS_INNER_COLS},
    mix::MixOperation,
    Blake2bCompressInnerChip, MIX_INDEX, NUM_MIX_ROUNDS, NUM_STATE_WORDS_PER_CALL, OPERATION_COUNT,
    SIGMA_PERMUTATIONS,
};

impl<F> BaseAir<F> for Blake2bCompressInnerChip {
    fn width(&self) -> usize {
        NUM_BLAKE2B_COMPRESS_INNER_COLS
    }
}

impl<AB> Air<AB> for Blake2bCompressInnerChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake2bCompressInnerCols<AB::Var> = main.row_slice(0).borrow();
        let next: &Blake2bCompressInnerCols<AB::Var> = main.row_slice(1).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constraint_mix_operation(builder, local);
    }
}

impl Blake2bCompressInnerChip {
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

    /// Constrains the control flow flags such as the operation index and the mix round index.
    fn constrain_control_flow_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2bCompressInnerCols<AB::Var>,
        next: &Blake2bCompressInnerCols<AB::Var>,
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
                    .assert_eq(local.mix_round, next.mix_round);
            } else {
                builder
                    .when_transition()
                    .when(local.is_operation_index_n[i])
                    .assert_eq(
                        local.mix_round + AB::F::from_canonical_u16(1),
                        next.mix_round,
                    );
            }
        }
    }

    /// Constrains the memory access for the state and the message.
    fn constrain_memory<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2bCompressInnerCols<AB::Var>,
    ) {
        // Calculate the 4 indices to read from the state. This corresponds to a, b, c, d.
        for i in 0..STATE_ELE_PER_CALL {
            let index_to_read = {
                self.constrain_index_selector(
                    builder,
                    &local.is_operation_index_n,
                    local.operation_index,
                    local.is_real,
                );

                let mut acc = AB::Expr::from_canonical_usize(0);
                for operation in 0..OPERATION_COUNT {
                    acc += AB::Expr::from_canonical_usize(MIX_INDEX[operation][i])
                        * local.is_operation_index_n[operation];
                }
                acc
            };

            builder.assert_eq(local.state_index[i], index_to_read);
        }

        // Read & write the state.
        for i in 0..STATE_ELE_PER_CALL {
            builder.constraint_memory_access(
                local.segment,
                local.clk,
                local.state_ptr + local.state_index[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.state_reads_writes[i],
                local.is_real,
            );
        }

        // Calculate the indices to read from the message.
        for i in 0..MSG_ELE_PER_CALL {
            let index_to_read = {
                self.constrain_index_selector(
                    builder,
                    &local.is_mix_round_index_n,
                    local.mix_round,
                    local.is_real,
                );

                let mut acc = AB::Expr::from_canonical_usize(0);

                for round in 0..NUM_MIX_ROUNDS {
                    for operation in 0..OPERATION_COUNT {
                        acc += AB::Expr::from_canonical_usize(
                            SIGMA_PERMUTATIONS[round][2 * operation + i],
                        ) * local.is_operation_index_n[operation]
                            * local.is_mix_round_index_n[round];
                    }
                }
                acc
            };
            builder.assert_eq(local.message_index[i], index_to_read);
        }

        // Read the message.
        for i in 0..MSG_ELE_PER_CALL {
            builder.constraint_memory_access(
                local.segment,
                local.clk,
                local.message_ptr + local.message_index[i] * AB::F::from_canonical_usize(WORD_SIZE),
                &local.message_reads[i],
                local.is_real,
            );
        }
    }

    /// Constrains the `mix` operation.
    fn constraint_mix_operation<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2bCompressInnerCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);

        // Apply the `mix` operation.
        // a, b, c, d, x, y are in u64. each of them are in 32 bits limbs.
        // a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, d_lo, d_hi, x_lo, x_hi, y_lo, y_hi
        // are in u32.
        let input = [
            local.state_reads_writes[0].prev_value,
            local.state_reads_writes[1].prev_value,
            local.state_reads_writes[2].prev_value,
            local.state_reads_writes[3].prev_value,
            local.state_reads_writes[4].prev_value,
            local.state_reads_writes[5].prev_value,
            local.state_reads_writes[6].prev_value,
            local.state_reads_writes[7].prev_value,
            local.message_reads[0].access.value,
            local.message_reads[1].access.value,
            local.message_reads[2].access.value,
            local.message_reads[3].access.value,
        ];

        // Apply the `mix` operation.
        MixOperation::<AB::F>::eval(builder, input, local.mix, local.is_real);

        // Finally, the results of the `mix` function should be written to the memory.
        for i in 0..NUM_STATE_WORDS_PER_CALL {
            for j in 0..WORD_SIZE {
                builder.when(local.is_real).assert_eq(
                    local.state_reads_writes[i].access.value[j],
                    local.mix.result[i][j],
                );
            }
        }
    }
}
