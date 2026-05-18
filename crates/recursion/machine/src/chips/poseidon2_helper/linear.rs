use core::borrow::Borrow;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{extension::BinomiallyExtendable, AbstractField, Field, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::MachineAir,
    next_multiple_of_32,
    operations::poseidon2::air::{external_linear_layer_mut, internal_linear_layer_mut},
};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{
    Address, Block, ExecutionRecord, Instruction, Poseidon2LinearLayerInstr,
    Poseidon2LinearLayerIo, RecursionProgram, D, PERMUTATION_WIDTH,
};
use std::{borrow::BorrowMut, iter::zip, mem::MaybeUninit};

use crate::builder::SP1RecursionAirBuilder;

pub const NUM_LINEAR_ENTRIES_PER_ROW: usize = 1;

#[derive(Default, Clone)]
pub struct Poseidon2LinearLayerChip;

pub const NUM_LINEAR_COLS: usize = core::mem::size_of::<Poseidon2LinearLayerCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2LinearLayerCols<F: Copy> {
    pub values: [Poseidon2LinearLayerValueCols<F>; NUM_LINEAR_ENTRIES_PER_ROW],
}
const NUM_LINEAR_VALUE_COLS: usize = core::mem::size_of::<Poseidon2LinearLayerValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2LinearLayerValueCols<F: Copy> {
    pub input: [Block<F>; 4],
}

pub const NUM_LINEAR_PREPROCESSED_COLS: usize =
    core::mem::size_of::<Poseidon2LinearLayerPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2LinearLayerPreprocessedCols<F: Copy> {
    pub accesses: [Poseidon2LinearLayerAccessCols<F>; NUM_LINEAR_ENTRIES_PER_ROW],
}

pub const NUM_LINEAR_ACCESS_COLS: usize =
    core::mem::size_of::<Poseidon2LinearLayerAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2LinearLayerAccessCols<F: Copy> {
    pub addrs: Poseidon2LinearLayerIo<Address<F>>,
    pub external: F,
    pub internal: F,
}

impl<F: Field> BaseAir<F> for Poseidon2LinearLayerChip {
    fn width(&self) -> usize {
        NUM_LINEAR_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for Poseidon2LinearLayerChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> &'static str {
        "Poseidon2LinearLayer"
    }

    fn preprocessed_width(&self) -> usize {
        NUM_LINEAR_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Poseidon2LinearLayer(x) => Some(x.as_ref()),
                _ => None,
            })
            .count();
        self.preprocessed_num_rows_with_instrs_len(program, instrs_len)
    }

    fn preprocessed_num_rows_with_instrs_len(
        &self,
        program: &Self::Program,
        instrs_len: usize,
    ) -> Option<usize> {
        let height = program.shape.as_ref().and_then(|shape| shape.height(self));
        let nb_rows = instrs_len.div_ceil(NUM_LINEAR_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
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

        let instrs = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Poseidon2LinearLayer(x) => Some(x.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let padded_nb_rows =
            self.preprocessed_num_rows_with_instrs_len(program, instrs.len()).unwrap();

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                padded_nb_rows * NUM_LINEAR_PREPROCESSED_COLS,
            )
        };

        unsafe {
            let padding_start = instrs.len() * NUM_LINEAR_ACCESS_COLS;
            let padding_size = padded_nb_rows * NUM_LINEAR_PREPROCESSED_COLS - padding_start;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_LINEAR_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_LINEAR_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let Poseidon2LinearLayerInstr { addrs, mults, external } = instr;
                let access: &mut Poseidon2LinearLayerAccessCols<_> = row.borrow_mut();
                access.addrs = addrs.to_owned();
                #[allow(clippy::needless_range_loop)]
                for i in 0..PERMUTATION_WIDTH / D {
                    assert_eq!(mults[i], F::one());
                }
                if *external {
                    access.external = F::one();
                    access.internal = F::zero();
                } else {
                    access.external = F::zero();
                    access.internal = F::one();
                }
            },
        );
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let events = &input.poseidon2_linear_layer_events;
        let nb_rows = events.len().div_ceil(NUM_LINEAR_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
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
        let events = &input.poseidon2_linear_layer_events;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_LINEAR_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_LINEAR_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_LINEAR_COLS)
        };

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_LINEAR_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_LINEAR_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut Poseidon2LinearLayerValueCols<_> = row.borrow_mut();
                cols.input = vals.input.to_owned();
            },
        );
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for Poseidon2LinearLayerChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2LinearLayerCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &Poseidon2LinearLayerPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            Poseidon2LinearLayerValueCols { input },
            Poseidon2LinearLayerAccessCols { addrs, external, internal },
        ) in zip(local.values, prep_local.accesses)
        {
            // Check that the `external`, `internal` flags are boolean, and at most one is on.
            let is_real = external + internal;
            builder.assert_bool(external);
            builder.assert_bool(internal);
            builder.assert_bool(is_real.clone());

            // Read the inputs from memory. The inputs are packed in extension elements.
            #[allow(clippy::needless_range_loop)]
            for i in 0..PERMUTATION_WIDTH / D {
                builder.receive_block(addrs.input[i], input[i], is_real.clone());
            }

            let mut state_external: [_; PERMUTATION_WIDTH] =
                core::array::from_fn(|_| AB::Expr::zero());
            let mut state_internal: [_; PERMUTATION_WIDTH] =
                core::array::from_fn(|_| AB::Expr::zero());

            // Unpack the extension elements into field elements.
            for i in 0..PERMUTATION_WIDTH / D {
                for j in 0..D {
                    state_external[i * D + j] = input[i].0[j].into();
                    state_internal[i * D + j] = input[i].0[j].into();
                }
            }

            // Apply the external/internal linear layer.
            external_linear_layer_mut(&mut state_external);
            internal_linear_layer_mut(&mut state_internal);

            // Write the output to memory for each case.
            for i in 0..PERMUTATION_WIDTH / D {
                builder.send_block(
                    Address(addrs.output[i].0.into()),
                    Block([
                        state_external[i * D].clone(),
                        state_external[i * D + 1].clone(),
                        state_external[i * D + 2].clone(),
                        state_external[i * D + 3].clone(),
                    ]),
                    external,
                );
                builder.send_block(
                    Address(addrs.output[i].0.into()),
                    Block([
                        state_internal[i * D].clone(),
                        state_internal[i * D + 1].clone(),
                        state_internal[i * D + 2].clone(),
                        state_internal[i * D + 3].clone(),
                    ]),
                    internal,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use slop_matrix::Matrix;
    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::ExecutionRecord;

    use super::Poseidon2LinearLayerChip;

    use crate::chips::test_fixtures;

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let trace = Poseidon2LinearLayerChip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let trace = Poseidon2LinearLayerChip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }
}
