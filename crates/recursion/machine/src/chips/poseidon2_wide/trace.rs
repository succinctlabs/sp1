use slop_air::BaseAir;
use slop_algebra::PrimeField32;
use slop_maybe_rayon::prelude::*;
use sp1_hypercube::{
    air::MachineAir,
    operations::poseidon2::{trace::populate_perm, WIDTH},
    pad_rows_recursion,
};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{ExecutionRecord, Instruction, RecursionProgram};
use std::{
    borrow::BorrowMut,
    mem::{size_of, MaybeUninit},
};

use super::{columns::preprocessed::Poseidon2PreprocessedColsWide, Poseidon2WideChip};
use crate::chips::mem::MemoryAccessCols;

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedColsWide<u8>>();

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    #[allow(clippy::uninlined_format_args)]
    fn name(&self) -> &'static str {
        match DEGREE {
            3 => "Poseidon2WideDeg3",
            9 => "Poseidon2WideDeg9",
            _ => panic!("unsupported DEGREE"),
        }
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let events = &input.poseidon2_events;
        Some(pad_rows_recursion(events.len(), height))
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
        buffer: &mut [MaybeUninit<F>],
    ) {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_trace_into only supports SP1Field field"
        );

        let padded_nb_rows = self.num_rows(input).unwrap();
        let num_columns = <Self as BaseAir<SP1Field>>::width(self);

        let events = &input.poseidon2_events;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * num_columns;
            let padding_size = (padded_nb_rows - num_event_rows) * num_columns;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * num_columns) };

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        values.par_chunks_mut(num_columns).enumerate().for_each(|(idx, row)| {
            if idx < events.len() {
                let event = events[idx];
                populate_perm::<F, DEGREE>(event.input, Some(event.output), row);
            } else {
                populate_perm::<F, DEGREE>([F::zero(); WIDTH], None, row);
            }
        });
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program
            .inner
            .iter()
            .filter(|instruction| matches!(instruction.inner(), Instruction::Poseidon2(_)))
            .count();
        self.preprocessed_num_rows_with_instrs_len(program, instrs_len)
    }

    fn preprocessed_num_rows_with_instrs_len(
        &self,
        program: &Self::Program,
        instrs_len: usize,
    ) -> Option<usize> {
        let height = program.shape.as_ref().and_then(|shape| shape.height(self));
        Some(pad_rows_recursion(instrs_len, height))
    }

    fn generate_preprocessed_trace_into(
        &self,
        program: &Self::Program,
        buffer: &mut [MaybeUninit<F>],
    ) {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_preprocessed_trace only supports SP1Field field"
        );

        // Allocating an intermediate `Vec` is faster.
        let instrs = program
            .inner
            .iter() // Faster than using `rayon` for some reason. Maybe vectorization?
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Poseidon2(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let padded_nb_rows =
            self.preprocessed_num_rows_with_instrs_len(program, instrs.len()).unwrap();

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH,
            )
        };

        unsafe {
            let padding_start = instrs.len() * PREPROCESSED_POSEIDON2_WIDTH;
            let padding_size = padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH - padding_start;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let populate_len = instrs.len() * PREPROCESSED_POSEIDON2_WIDTH;
        values[..populate_len]
            .par_chunks_mut(PREPROCESSED_POSEIDON2_WIDTH)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                // Set the memory columns. We read once, at the first iteration,
                // and write once, at the last iteration.
                *row.borrow_mut() = Poseidon2PreprocessedColsWide {
                    input: instr.addrs.input,
                    output: std::array::from_fn(|j| MemoryAccessCols {
                        addr: instr.addrs.output[j],
                        mult: instr.mults[j],
                    }),
                    is_real: F::one(),
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use crate::chips::{poseidon2_wide::Poseidon2WideChip, test_fixtures};
    use slop_matrix::Matrix;
    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::ExecutionRecord;

    const DEGREE_3: usize = 3;

    #[tokio::test]
    async fn test_generate_trace_deg_3() {
        let shard = test_fixtures::shard().await;
        let chip = Poseidon2WideChip::<DEGREE_3>;
        let trace = chip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn test_generate_preprocessed_trace_deg_3() {
        let program = &test_fixtures::program_with_input().await.0;
        let chip = Poseidon2WideChip::<DEGREE_3>;
        let trace = chip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }
}
