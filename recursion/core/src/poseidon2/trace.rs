use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::{air::MachineAir, utils::pad_rows_fixed};
use sp1_primitives::RC_16_30_U32;
use tracing::instrument;

use crate::{
    poseidon2_wide::{external_linear_layer, internal_linear_layer},
    runtime::{ExecutionRecord, RecursionProgram},
};

use super::{
    external::{NUM_POSEIDON2_COLS, WIDTH},
    Poseidon2Chip, Poseidon2Cols,
};

impl<F: PrimeField32> MachineAir<F> for Poseidon2Chip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Poseidon2".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate poseidon2 trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        // 1 round for memory input; 1 round for initialize; 8 rounds for external; 13 rounds for internal; 1 round for memory output
        let rounds_f = 8;
        let rounds_p = 13;
        let rounds = rounds_f + rounds_p + 3;
        let rounds_p_beginning = 2 + rounds_f / 2;
        let p_end = rounds_p_beginning + rounds_p;

        for poseidon2_event in input.poseidon2_events.iter() {
            let mut round_input = Default::default();
            for r in 0..rounds {
                let mut row = [F::zero(); NUM_POSEIDON2_COLS];
                let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::one();

                let is_receive = r == 0;
                let is_memory_read = r == 0;
                let is_initial_layer = r == 1;
                let is_external_layer =
                    (r >= 2 && r < rounds_p_beginning) || (r >= p_end && r < p_end + rounds_f / 2);
                let is_internal_layer = r >= rounds_p_beginning && r < p_end;
                let is_memory_write = r == rounds - 1;

                let sum = (is_memory_read as u32)
                    + (is_initial_layer as u32)
                    + (is_external_layer as u32)
                    + (is_internal_layer as u32)
                    + (is_memory_write as u32);
                assert!(
                    sum == 0 || sum == 1,
                    "{} {} {} {} {}",
                    is_memory_read,
                    is_initial_layer,
                    is_external_layer,
                    is_internal_layer,
                    is_memory_write
                );

                cols.clk = poseidon2_event.clk;
                cols.dst_input = poseidon2_event.dst;
                cols.left_input = poseidon2_event.left;
                cols.right_input = poseidon2_event.right;
                cols.rounds[r] = F::one();

                if is_receive {
                    cols.do_receive = F::one();
                }

                if is_memory_read || is_memory_write {
                    let memory_access_cols = cols.round_specific_cols.memory_access_mut();

                    if is_memory_read {
                        memory_access_cols.addr_first_half = poseidon2_event.left;
                        memory_access_cols.addr_second_half = poseidon2_event.right;
                        for i in 0..WIDTH {
                            memory_access_cols.mem_access[i]
                                .populate(&poseidon2_event.input_records[i]);
                        }
                    } else {
                        memory_access_cols.addr_first_half = poseidon2_event.dst;
                        memory_access_cols.addr_second_half =
                            poseidon2_event.dst + F::from_canonical_usize(WIDTH / 2);
                        for i in 0..WIDTH {
                            memory_access_cols.mem_access[i]
                                .populate(&poseidon2_event.result_records[i]);
                        }
                    }
                    cols.do_memory = F::one();
                } else {
                    let computation_cols = cols.round_specific_cols.computation_mut();

                    if is_initial_layer {
                        round_input = poseidon2_event.input;
                    }

                    computation_cols.input = round_input;

                    if is_initial_layer {
                        // Don't apply the round constants.
                        computation_cols
                            .add_rc
                            .copy_from_slice(&computation_cols.input);
                    } else if is_external_layer {
                        // Apply the round constants.
                        for j in 0..WIDTH {
                            computation_cols.add_rc[j] = computation_cols.input[j]
                                + F::from_wrapped_u32(RC_16_30_U32[r - 2][j]);
                        }
                    } else {
                        // Apply the round constants only on the first element.
                        computation_cols
                            .add_rc
                            .copy_from_slice(&computation_cols.input);
                        computation_cols.add_rc[0] =
                            computation_cols.input[0] + F::from_wrapped_u32(RC_16_30_U32[r - 2][0]);
                    };

                    // Apply the sbox.
                    for j in 0..WIDTH {
                        let sbox_deg_3 = computation_cols.add_rc[j]
                            * computation_cols.add_rc[j]
                            * computation_cols.add_rc[j];
                        computation_cols.sbox_deg_3[j] = sbox_deg_3;
                        computation_cols.sbox_deg_7[j] =
                            sbox_deg_3 * sbox_deg_3 * computation_cols.add_rc[j];
                    }

                    // What state to use for the linear layer.
                    let mut state = if is_initial_layer {
                        computation_cols.add_rc
                    } else if is_external_layer {
                        computation_cols.sbox_deg_7
                    } else {
                        let mut state = computation_cols.add_rc;
                        state[0] = computation_cols.sbox_deg_7[0];
                        state
                    };

                    // Apply either the external or internal linear layer.
                    if is_initial_layer || is_external_layer {
                        external_linear_layer(&mut state);
                    } else if is_internal_layer {
                        internal_linear_layer(&mut state)
                    }

                    // Copy the state to the output.
                    computation_cols.output.copy_from_slice(&state);

                    round_input = computation_cols.output;
                }

                rows.push(row);
            }
        }

        let num_real_rows = rows.len();

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut rows,
                || [F::zero(); NUM_POSEIDON2_COLS],
                self.fixed_log2_rows,
            );
        }

        let mut round_num = 0;
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();
            cols.rounds[round_num] = F::one();

            round_num = (round_num + 1) % rounds;
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_COLS,
        )
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.poseidon2_events.is_empty()
    }
}
