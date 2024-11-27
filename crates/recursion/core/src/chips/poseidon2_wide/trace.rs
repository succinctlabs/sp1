use std::{borrow::BorrowMut, mem::size_of};

use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use sp1_core_machine::utils::next_power_of_two;
use sp1_primitives::RC_16_30_U32;
use sp1_stark::air::MachineAir;
use tracing::instrument;

use crate::{
    chips::mem::MemoryAccessCols, instruction::Instruction::Poseidon2, ExecutionRecord,
    RecursionProgram,
};

use super::columns::preprocessed::Poseidon2PreprocessedCols;

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2WideDeg{}", DEGREE)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let padded_nb_rows = match input.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(events.len(), None),
        };
        let num_columns = <Self as BaseAir<F>>::width(self);
        let mut values = vec![F::zero(); padded_nb_rows * num_columns];

        let populate_len = events.len() * num_columns;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop.par_chunks_mut(num_columns).zip_eq(&input.poseidon2_events).for_each(
                    |(row, &event)| {
                        self.populate_perm(event.input, Some(event.output), row);
                    },
                )
            },
            || {
                let mut dummy_row = vec![F::zero(); num_columns];
                self.populate_perm([F::zero(); WIDTH], None, &mut dummy_row);
                values_dummy
                    .par_chunks_mut(num_columns)
                    .for_each(|row| row.copy_from_slice(&dummy_row))
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, num_columns)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let instrs = program
            .instructions
            .iter() // Faster than using `rayon` for some reason. Maybe vectorization?
            .filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let padded_nb_rows = match program.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(instrs.len(), None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH];

        let populate_len = instrs.len() * PREPROCESSED_POSEIDON2_WIDTH;
        values[..populate_len]
            .par_chunks_mut(PREPROCESSED_POSEIDON2_WIDTH)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                // Set the memory columns. We read once, at the first iteration,
                // and write once, at the last iteration.
                *row.borrow_mut() = Poseidon2PreprocessedCols {
                    input: instr.addrs.input,
                    output: std::array::from_fn(|j| MemoryAccessCols {
                        addr: instr.addrs.output[j],
                        mult: instr.mults[j],
                    }),
                    is_real_neg: F::neg_one(),
                }
            });
        Some(RowMajorMatrix::new(values, PREPROCESSED_POSEIDON2_WIDTH))
    }
}

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    fn populate_perm<F: PrimeField32>(
        &self,
        input: [F; WIDTH],
        expected_output: Option<[F; WIDTH]>,
        input_row: &mut [F],
    ) {
        {
            let permutation = permutation_mut::<F, DEGREE>(input_row);

            let (
                external_rounds_state,
                internal_rounds_state,
                internal_rounds_s0,
                mut external_sbox,
                mut internal_sbox,
                output_state,
            ) = permutation.get_cols_mut();

            external_rounds_state[0] = input;

            // Apply the first half of external rounds.
            for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                let next_state =
                    self.populate_external_round(external_rounds_state, &mut external_sbox, r);
                if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                    *internal_rounds_state = next_state;
                } else {
                    external_rounds_state[r + 1] = next_state;
                }
            }

            // Apply the internal rounds.
            external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] = self.populate_internal_rounds(
                internal_rounds_state,
                internal_rounds_s0,
                &mut internal_sbox,
            );

            // Apply the second half of external rounds.
            for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                let next_state =
                    self.populate_external_round(external_rounds_state, &mut external_sbox, r);
                if r == NUM_EXTERNAL_ROUNDS - 1 {
                    for i in 0..WIDTH {
                        output_state[i] = next_state[i];
                        if let Some(expected_output) = expected_output {
                            assert_eq!(expected_output[i], next_state[i]);
                        }
                    }
                } else {
                    external_rounds_state[r + 1] = next_state;
                }
            }
        }
    }

    fn populate_external_round<F: PrimeField32>(
        &self,
        external_rounds_state: &[[F; WIDTH]],
        sbox: &mut Option<&mut [[F; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        r: usize,
    ) -> [F; WIDTH] {
        let mut state = {
            // For the first round, apply the linear layer.
            let round_state: &[F; WIDTH] = if r == 0 {
                &external_linear_layer(&external_rounds_state[r])
            } else {
                &external_rounds_state[r]
            };

            // Add round constants.
            //
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the
            // sbox.
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 { r } else { r + NUM_INTERNAL_ROUNDS };
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

            if let Some(sbox) = sbox.as_deref_mut() {
                sbox[r] = sbox_deg_3;
            }

            sbox_deg_7
        };

        // Apply the linear layer.
        external_linear_layer_mut(&mut state);
        state
    }

    fn populate_internal_rounds<F: PrimeField32>(
        &self,
        internal_rounds_state: &[F; WIDTH],
        internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
        sbox: &mut Option<&mut [F; NUM_INTERNAL_ROUNDS]>,
    ) -> [F; WIDTH] {
        let mut state: [F; WIDTH] = *internal_rounds_state;
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
            internal_linear_layer_mut(&mut state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = state[0];
            }
        }

        let ret_state = state;

        if let Some(sbox) = sbox.as_deref_mut() {
            *sbox = sbox_deg_3;
        }

        ret_state
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use sp1_stark::{air::MachineAir, inner_perm};
    use zkhash::ark_ff::UniformRand;

    use crate::{
        chips::poseidon2_wide::{Poseidon2WideChip, WIDTH},
        Address, ExecutionRecord, Poseidon2Event, Poseidon2Instr, Poseidon2Io,
    };

    use super::*;

    #[test]
    fn generate_trace_deg_3() {
        type F = BabyBear;
        let input_0 = [F::one(); WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };
        let chip_3 = Poseidon2WideChip::<3>;
        let _: RowMajorMatrix<F> = chip_3.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    #[test]
    fn generate_trace_deg_9() {
        type F = BabyBear;
        let input_0 = [F::one(); WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };
        let chip_9 = Poseidon2WideChip::<9>;
        let _: RowMajorMatrix<F> = chip_9.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_trace_deg_3_ffi_eq_rust() {
        type F = BabyBear;
        let input_0 = [F::one(); WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };

        let chip = Poseidon2WideChip::<3>;
        let trace_rust = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi::<3>(&shard);

        assert_eq!(trace_ffi, trace_rust);
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_trace_deg_9_ffi_eq_rust() {
        type F = BabyBear;
        let input_0 = [F::one(); WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };

        let chip = Poseidon2WideChip::<9>;
        let trace_rust = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi::<9>(&shard);

        assert_eq!(trace_ffi, trace_rust);
    }

    #[cfg(feature = "sys")]
    fn generate_trace_ffi<const DEGREE: usize>(
        input: &ExecutionRecord<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;
        let padded_nb_rows = match input.fixed_log2_rows(&Poseidon2WideChip::<DEGREE>) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(input.poseidon2_events.len(), None),
        };
        let num_columns =
            <Poseidon2WideChip<DEGREE> as BaseAir<F>>::width(&Poseidon2WideChip::<DEGREE>);
        let mut values = vec![F::zero(); padded_nb_rows * num_columns];

        let populate_len = input.poseidon2_events.len() * num_columns;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);

        join(
            || {
                values_pop
                    .par_chunks_mut(num_columns)
                    .zip_eq(&input.poseidon2_events)
                    .for_each(|(row, event)| populate_perm_ffi::<DEGREE>(&event.input, row))
            },
            || {
                let mut dummy_row = vec![F::zero(); num_columns];
                populate_perm_ffi::<DEGREE>(&[F::zero(); WIDTH], &mut dummy_row);
                values_dummy
                    .par_chunks_mut(num_columns)
                    .for_each(|row| row.copy_from_slice(&dummy_row))
            },
        );

        RowMajorMatrix::new(values, num_columns)
    }

    #[cfg(feature = "sys")]
    fn populate_perm_ffi<const DEGREE: usize>(
        input: &[BabyBear; WIDTH],
        input_row: &mut [BabyBear],
    ) {
        unsafe {
            crate::sys::poseidon2_wide_event_to_row_babybear(
                input.as_ptr(),
                input_row.as_mut_ptr(),
                DEGREE == 3,
            );
        }
    }

    #[test]
    fn generate_preprocessed_trace() {
        type F = BabyBear;

        let program = RecursionProgram::<BabyBear> {
            instructions: vec![Poseidon2(Box::new(Poseidon2Instr {
                addrs: Poseidon2Io {
                    input: [Address(F::one()); WIDTH],
                    output: [Address(F::two()); WIDTH],
                },
                mults: [F::one(); WIDTH],
            }))],
            ..Default::default()
        };

        let chip_9 = Poseidon2WideChip::<9>;
        let preprocessed: Option<RowMajorMatrix<F>> = chip_9.generate_preprocessed_trace(&program);
        assert!(preprocessed.is_some());
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_preprocessed_trace_ffi_eq_rust() {
        type F = BabyBear;

        let program = RecursionProgram::<BabyBear> {
            instructions: vec![Poseidon2(Box::new(Poseidon2Instr {
                addrs: Poseidon2Io {
                    input: [Address(F::one()); WIDTH],
                    output: [Address(F::two()); WIDTH],
                },
                mults: [F::one(); WIDTH],
            }))],
            ..Default::default()
        };

        let chip = Poseidon2WideChip::<9>;
        let trace_rust = chip.generate_preprocessed_trace(&program).unwrap();
        let trace_ffi = generate_preprocessed_trace_ffi(&program);

        assert_eq!(trace_ffi, trace_rust);
    }

    #[cfg(feature = "sys")]
    fn generate_preprocessed_trace_ffi(
        program: &RecursionProgram<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;

        let instrs = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let padded_nb_rows = match program.fixed_log2_rows(&Poseidon2WideChip::<9>) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(instrs.len(), None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH];

        let populate_len = instrs.len() * PREPROCESSED_POSEIDON2_WIDTH;
        values[..populate_len]
            .par_chunks_mut(PREPROCESSED_POSEIDON2_WIDTH)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                let cols: &mut Poseidon2PreprocessedCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::poseidon2_wide_instr_to_row_babybear(instr, cols);
                }
            });

        RowMajorMatrix::new(values, PREPROCESSED_POSEIDON2_WIDTH)
    }
}
