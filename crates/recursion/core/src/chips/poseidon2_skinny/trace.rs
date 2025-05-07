use crate::{
    chips::poseidon2_skinny::{
        columns::{Poseidon2 as Poseidon2Cols, NUM_POSEIDON2_COLS},
        Poseidon2SkinnyChip, NUM_EXTERNAL_ROUNDS,
    },
    instruction::Instruction::Poseidon2,
    ExecutionRecord, Poseidon2Io, Poseidon2SkinnyInstr,
};
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use sp1_core_machine::utils::next_power_of_two;
use sp1_stark::air::MachineAir;
use std::{borrow::BorrowMut, mem::size_of};
use tracing::instrument;

use super::columns::preprocessed::Poseidon2PreprocessedCols;

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedCols<u8>>();
pub const OUTPUT_ROUND_IDX: usize = NUM_EXTERNAL_ROUNDS + 2;

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2SkinnyChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2SkinnyDeg{}", DEGREE)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.poseidon2_events;
        Some(next_power_of_two(events.len() * (OUTPUT_ROUND_IDX + 1), input.fixed_log2_rows(self)))
    }

    #[instrument(name = "generate poseidon2 skinny trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<BabyBear>(),
            "generate_trace only supports BabyBear field"
        );

        let mut rows = Vec::new();

        let events = unsafe {
            std::mem::transmute::<&Vec<Poseidon2Io<F>>, &Vec<Poseidon2Io<BabyBear>>>(
                &input.poseidon2_events,
            )
        };
        for event in events {
            let mut row_add = [[BabyBear::zero(); NUM_POSEIDON2_COLS]; NUM_EXTERNAL_ROUNDS + 3];
            unsafe {
                crate::sys::poseidon2_skinny_event_to_row_babybear(
                    event,
                    row_add.as_mut_ptr() as *mut Poseidon2Cols<BabyBear>,
                );
            }
            rows.extend(row_add.into_iter());
        }

        rows.resize(self.num_rows(input).unwrap(), [BabyBear::zero(); NUM_POSEIDON2_COLS]);

        RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<BabyBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<BabyBear>>(),
                )
            },
            NUM_POSEIDON2_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_power_of_two(instrs_len, program.fixed_log2_rows(self)))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<BabyBear>(),
            "generate_preprocessed_trace only supports BabyBear field"
        );

        let instructions = program.inner.iter().filter_map(|instruction| match instruction {
            Poseidon2(instr) => Some(unsafe {
                std::mem::transmute::<
                    &Box<Poseidon2SkinnyInstr<F>>,
                    &Box<Poseidon2SkinnyInstr<BabyBear>>,
                >(instr)
            }),
            _ => None,
        });

        let num_instructions =
            program.inner.iter().filter(|instr| matches!(instr, Poseidon2(_))).count();
        let mut rows = vec![
            [BabyBear::zero(); PREPROCESSED_POSEIDON2_WIDTH];
            num_instructions * (NUM_EXTERNAL_ROUNDS + 3)
        ];
        instructions.zip_eq(&rows.iter_mut().chunks(NUM_EXTERNAL_ROUNDS + 3)).for_each(
            |(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();
                    unsafe {
                        crate::sys::poseidon2_skinny_instr_to_row_babybear(instruction, i, cols);
                    }
                });
            },
        );

        rows.resize(
            self.preprocessed_num_rows(program, rows.len()).unwrap(),
            [BabyBear::zero(); PREPROCESSED_POSEIDON2_WIDTH],
        );

        Some(RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<BabyBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<BabyBear>>(),
                )
            },
            PREPROCESSED_POSEIDON2_WIDTH,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chips::{
            mem::MemoryAccessCols,
            poseidon2_skinny::{
                external_linear_layer, internal_linear_layer, Poseidon2SkinnyChip,
                NUM_INTERNAL_ROUNDS,
            },
            test_fixtures,
        },
        ExecutionRecord, RecursionProgram, WIDTH,
    };
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use sp1_primitives::RC_16_30_U32;
    use sp1_stark::air::MachineAir;
    use std::{array, borrow::Borrow};

    use super::*;

    const INTERNAL_ROUND_IDX: usize = NUM_EXTERNAL_ROUNDS / 2 + 1;
    const INPUT_ROUND_IDX: usize = 0;
    const DEGREE: usize = 9;

    fn generate_trace_reference<const DEGREE: usize>(
        input: &ExecutionRecord<BabyBear>,
        _: &mut ExecutionRecord<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;

        let mut rows = Vec::new();

        for event in &input.poseidon2_events {
            // We have one row for input, one row for output, NUM_EXTERNAL_ROUNDS rows for the
            // external rounds, and one row for all internal rounds.
            let mut row_add = [[F::zero(); NUM_POSEIDON2_COLS]; NUM_EXTERNAL_ROUNDS + 3];

            // The first row should have event.input and [event.input[0].clone();
            // NUM_INTERNAL_ROUNDS-1] in its state columns. The sbox_state will be
            // modified in the computation of the first row.
            {
                let (first_row, second_row) = &mut row_add[0..2].split_at_mut(1);
                let input_cols: &mut Poseidon2Cols<F> = first_row[0].as_mut_slice().borrow_mut();
                input_cols.state_var = event.input;

                let next_cols: &mut Poseidon2Cols<F> = second_row[0].as_mut_slice().borrow_mut();
                next_cols.state_var = event.input;
                external_linear_layer(&mut next_cols.state_var);
            }

            // For each external round, and once for all the internal rounds at the same time, apply
            // the corresponding operation. This will change the state and internal_rounds_s0
            // variable in row r+1.
            for i in 1..OUTPUT_ROUND_IDX {
                let next_state_var = {
                    let cols: &mut Poseidon2Cols<F> = row_add[i].as_mut_slice().borrow_mut();
                    let state = cols.state_var;

                    if i != INTERNAL_ROUND_IDX {
                        populate_external_round::<F>(&state, i - 1)
                    } else {
                        // Populate the internal rounds.
                        populate_internal_rounds::<F>(&state, &mut cols.internal_rounds_s0)
                    }
                };
                let next_row_cols: &mut Poseidon2Cols<F> =
                    row_add[i + 1].as_mut_slice().borrow_mut();
                next_row_cols.state_var = next_state_var;
            }

            // Check that the permutation is computed correctly.
            {
                let last_row_cols: &Poseidon2Cols<F> =
                    row_add[OUTPUT_ROUND_IDX].as_slice().borrow();
                debug_assert_eq!(last_row_cols.state_var, event.output);
            }
            rows.extend(row_add.into_iter());
        }

        // Pad the trace to a power of two.
        // This will need to be adjusted when the AIR constraints are implemented.
        rows.resize(
            Poseidon2SkinnyChip::<DEGREE>::default().num_rows(input).unwrap(),
            [F::zero(); NUM_POSEIDON2_COLS],
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_POSEIDON2_COLS)
    }

    fn populate_external_round<F: PrimeField32>(round_state: &[F; WIDTH], r: usize) -> [F; WIDTH] {
        let mut state = {
            // Add round constants.

            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the
            // sbox.
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 { r } else { r + NUM_INTERNAL_ROUNDS - 1 };
            let mut add_rc = *round_state;
            (0..WIDTH).for_each(|i| add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]));

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
            // part of the sbox in the constraint for the linear layer
            let mut sbox_deg_7: [F; 16] = [F::zero(); WIDTH];
            for i in 0..WIDTH {
                let sbox_deg_3 = add_rc[i] * add_rc[i] * add_rc[i];
                sbox_deg_7[i] = sbox_deg_3 * sbox_deg_3 * add_rc[i];
            }

            sbox_deg_7
        };
        // Apply the linear layer.
        external_linear_layer(&mut state);
        state
    }

    fn populate_internal_rounds<F: PrimeField32>(
        state: &[F; WIDTH],
        internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
    ) -> [F; WIDTH] {
        let mut new_state = *state;
        (0..NUM_INTERNAL_ROUNDS).for_each(|r| {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = new_state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, just like for external rounds.
            let sbox_deg_3 = add_rc * add_rc * add_rc;
            let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc;

            // Apply the linear layer.
            new_state[0] = sbox_deg_7;
            internal_linear_layer(&mut new_state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = new_state[0];
            }
        });

        new_state
    }

    #[test]
    fn test_generate_trace() {
        let shard = test_fixtures::shard();
        let mut execution_record = test_fixtures::default_execution_record();
        let chip = Poseidon2SkinnyChip::<DEGREE>::default();
        let trace = chip.generate_trace(&shard, &mut execution_record);
        assert!(trace.height() >= test_fixtures::MIN_TEST_CASES);

        assert_eq!(trace, generate_trace_reference::<DEGREE>(&shard, &mut execution_record));
    }

    fn generate_preprocessed_trace_reference<const DEGREE: usize>(
        program: &RecursionProgram<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;

        let instructions = program.inner.iter().filter_map(|instruction| match instruction {
            Poseidon2(instr) => Some(instr),
            _ => None,
        });

        let num_instructions =
            program.inner.iter().filter(|instr| matches!(instr, Poseidon2(_))).count();
        let mut rows = vec![
            [F::zero(); PREPROCESSED_POSEIDON2_WIDTH];
            num_instructions * (NUM_EXTERNAL_ROUNDS + 3)
        ];

        // Iterate over the instructions and take NUM_EXTERNAL_ROUNDS + 3 rows for each instruction.
        // We have one extra round for the internal rounds, one extra round for the input,
        // and one extra round for the output.
        instructions.zip_eq(&rows.iter_mut().chunks(NUM_EXTERNAL_ROUNDS + 3)).for_each(
            |(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();

                    // Set the round-counter columns.
                    cols.round_counters_preprocessed.is_input_round =
                        F::from_bool(i == INPUT_ROUND_IDX);
                    let is_external_round =
                        i != INPUT_ROUND_IDX && i != INTERNAL_ROUND_IDX && i != OUTPUT_ROUND_IDX;
                    cols.round_counters_preprocessed.is_external_round =
                        F::from_bool(is_external_round);
                    cols.round_counters_preprocessed.is_internal_round =
                        F::from_bool(i == INTERNAL_ROUND_IDX);

                    (0..WIDTH).for_each(|j| {
                        cols.round_counters_preprocessed.round_constants[j] = if is_external_round {
                            let r = i - 1;
                            let round = if i < INTERNAL_ROUND_IDX {
                                r
                            } else {
                                r + NUM_INTERNAL_ROUNDS - 1
                            };

                            F::from_wrapped_u32(RC_16_30_U32[round][j])
                        } else if i == INTERNAL_ROUND_IDX {
                            F::from_wrapped_u32(RC_16_30_U32[NUM_EXTERNAL_ROUNDS / 2 + j][0])
                        } else {
                            F::zero()
                        };
                    });

                    // Set the memory columns. We read once, at the first iteration,
                    // and write once, at the last iteration.
                    if i == INPUT_ROUND_IDX {
                        cols.memory_preprocessed = instruction
                            .addrs
                            .input
                            .map(|addr| MemoryAccessCols { addr, mult: F::neg_one() });
                    } else if i == OUTPUT_ROUND_IDX {
                        cols.memory_preprocessed = array::from_fn(|i| MemoryAccessCols {
                            addr: instruction.addrs.output[i],
                            mult: instruction.mults[i],
                        });
                    }
                });
            },
        );

        // Pad the trace to a power of two.
        // This may need to be adjusted when the AIR constraints are implemented.
        rows.resize(
            Poseidon2SkinnyChip::<DEGREE>::default()
                .preprocessed_num_rows(program, rows.len())
                .unwrap(),
            [BabyBear::zero(); PREPROCESSED_POSEIDON2_WIDTH],
        );

        let trace_rows = rows.into_iter().flatten().collect::<Vec<_>>();
        RowMajorMatrix::new(trace_rows, PREPROCESSED_POSEIDON2_WIDTH)
    }

    #[test]
    #[ignore = "Failing due to merge conflicts. Will be fixed shortly."]
    fn generate_preprocessed_trace() {
        let program = test_fixtures::program();
        let chip = Poseidon2SkinnyChip::<DEGREE>::default();
        let trace = chip.generate_preprocessed_trace(&program).unwrap();
        assert!(trace.height() >= test_fixtures::MIN_TEST_CASES);

        assert_eq!(trace, generate_preprocessed_trace_reference::<DEGREE>(&program));
    }
}
