use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core::{air::MachineAir, utils::pad_rows_fixed};
use sp1_primitives::RC_16_30_U32;
use tracing::instrument;

use crate::{
    poseidon2::Poseidon2Event,
    poseidon2_wide::{
        columns::{Poseidon2Cols, NUM_POSEIDON2_COLS},
        external_linear_layer, NUM_EXTERNAL_ROUNDS, WIDTH,
    },
    runtime::{ExecutionRecord, RecursionProgram},
};

use super::{
    columns::Poseidon2Permutation, internal_linear_layer, Poseidon2WideChip, NUM_INTERNAL_ROUNDS,
};

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2Wide {}", DEGREE)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let num_columns = NUM_POSEIDON2_COLS;

        for event in &input.poseidon2_events {
            match event {
                Poseidon2Event::Compress(compress_event) => {
                    let mut input_row = vec![F::zero(); NUM_POSEIDON2_COLS];

                    let cols: &mut Poseidon2Cols<F> = input_row.as_mut_slice().borrow_mut();
                    cols.is_compress = F::one();
                    cols.is_syscall = F::one();
                    cols.is_input = F::one();
                    cols.do_perm = F::one();

                    let input_cols = cols.syscall_input.compress_mut();
                    input_cols.clk = compress_event.clk;
                    input_cols.dst_ptr = compress_event.dst;
                    input_cols.left_ptr = compress_event.left;
                    input_cols.right_ptr = compress_event.right;

                    let compress_cols = cols.cols.compress_mut();

                    // Apply the initial round.
                    for i in 0..WIDTH {
                        compress_cols.input[i].populate(&compress_event.input_records[i]);
                    }

                    let p2_perm_cols = &mut compress_cols.permutation_cols;

                    p2_perm_cols.external_rounds_state[0] = compress_event.input;
                    external_linear_layer(&mut p2_perm_cols.external_rounds_state[0]);

                    // Apply the first half of external rounds.
                    for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                        let next_state = populate_external_round(p2_perm_cols, r);

                        if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                            p2_perm_cols.internal_rounds_state = next_state;
                        } else {
                            p2_perm_cols.external_rounds_state[r + 1] = next_state;
                        }
                    }

                    // Apply the internal rounds.
                    p2_perm_cols.external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] =
                        populate_internal_rounds(p2_perm_cols);

                    // Apply the second half of external rounds.
                    for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                        let next_state = populate_external_round(p2_perm_cols, r);
                        if r == NUM_EXTERNAL_ROUNDS - 1 {
                            for i in 0..WIDTH {
                                p2_perm_cols.output_state[i] = next_state[i];
                                assert_eq!(
                                    compress_event.result_records[i].value[0],
                                    next_state[i]
                                );
                            }
                        } else {
                            p2_perm_cols.external_rounds_state[r + 1] = next_state;
                        }
                    }

                    rows.push(input_row);

                    let mut output_row = vec![F::zero(); NUM_POSEIDON2_COLS];
                    let cols: &mut Poseidon2Cols<F> = output_row.as_mut_slice().borrow_mut();
                    cols.is_compress = F::one();
                    let input_cols = cols.syscall_input.compress_mut();
                    input_cols.clk = compress_event.clk;
                    input_cols.dst_ptr = compress_event.dst;
                    input_cols.left_ptr = compress_event.left;
                    input_cols.right_ptr = compress_event.right;

                    let output_cols = cols.cols.output_mut();

                    for i in 0..WIDTH {
                        output_cols.output_memory[i].populate(&compress_event.result_records[i]);
                    }

                    rows.push(output_row);
                }

                Poseidon2Event::Absorb(_) | Poseidon2Event::Finalize(_) => {
                    todo!();
                } // Poseidon2Event::Absorb(absorb_event) => {
                  //     cols.is_absorb = F::one();

                  //     let input_cols = cols.syscall_input.absorb_mut();
                  //     input_cols.clk = absorb_event.clk;
                  //     input_cols.input_ptr = absorb_event.input_ptr;
                  //     input_cols.len = F::from_canonical_usize(absorb_event.input_len);
                  //     input_cols.hash_num = absorb_event.hash_num;
                  // }

                  // Poseidon2Event::Finalize(finalize_event) => {
                  //     cols.is_finalize = F::one();

                  //     let input_cols = cols.syscall_input.finalize_mut();
                  //     input_cols.clk = finalize_event.clk;
                  //     input_cols.hash_num = finalize_event.hash_num;
                  //     input_cols.output_ptr = finalize_event.output_ptr;
                  // }
            }

            //     for i in 0..WIDTH {
            //         memory.output[i].populate(&event.result_records[i]);
            //     }
        }

        println!("run real rows is {:?}", rows.len());

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); num_columns],
            self.fixed_log2_rows,
        );

        // Convert the trace to a row major matrix.
        let trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), num_columns);

        #[cfg(debug_assertions)]
        println!(
            "poseidon2 wide trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.poseidon2_events.is_empty()
    }
}

fn populate_external_round<F: PrimeField32>(
    p2_perm_cols: &mut Poseidon2Permutation<F>,
    r: usize,
) -> [F; WIDTH] {
    let mut state = {
        let round_state: &mut [F; WIDTH] = p2_perm_cols.external_rounds_state[r].borrow_mut();

        // Add round constants.
        //
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, and instead include it in the constraint for the x^3 part of the sbox.
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        let mut add_rc = *round_state;
        for i in 0..WIDTH {
            add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
        }

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
        // part of the sbox in the constraint for the linear layer
        let mut sbox_deg_7: [F; 16] = [F::zero(); WIDTH];
        let mut sbox_deg_3: [F; 16] = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
            sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
        }

        p2_perm_cols.external_rounds_sbox[r] = sbox_deg_3;

        sbox_deg_7
    };

    // Apply the linear layer.
    external_linear_layer(&mut state);
    state
}

fn populate_internal_rounds<F: PrimeField32>(
    p2_perm_cols: &mut Poseidon2Permutation<F>,
) -> [F; WIDTH] {
    let mut state: [F; WIDTH] = p2_perm_cols.internal_rounds_state;
    let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::zero(); NUM_INTERNAL_ROUNDS];
    for r in 0..NUM_INTERNAL_ROUNDS {
        // Add the round constant to the 0th state element.
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, just like for external rounds.
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, just like for external rounds.
        sbox_deg_3[r] = add_rc * add_rc * add_rc;
        let sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;

        // Apply the linear layer.
        state[0] = sbox_deg_7;
        internal_linear_layer(&mut state);

        // Optimization: since we're only applying the sbox to the 0th state element, we only
        // need to have columns for the 0th state element at every step. This is because the
        // linear layer is degree 1, so all state elements at the end can be expressed as a
        // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
        // state element at rounds prior to the current round
        if r < NUM_INTERNAL_ROUNDS - 1 {
            p2_perm_cols.internal_rounds_s0[r] = state[0];
        }
    }

    let ret_state = state;

    p2_perm_cols.internal_rounds_sbox = sbox_deg_3;

    ret_state
}
