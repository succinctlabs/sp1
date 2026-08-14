use core::borrow::Borrow;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{extension::BinomiallyExtendable, Field, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, pad_rows_recursion};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{
    Address, Block, ExecutionRecord, ExtFeltInstr, Instruction, RecursionProgram, D,
};
use std::{borrow::BorrowMut, iter::zip, mem::MaybeUninit};

use crate::builder::SP1RecursionAirBuilder;

pub const NUM_CONVERT_ENTRIES_PER_ROW: usize = 1;

#[derive(Default, Clone)]
pub struct ConvertChip;

pub const NUM_CONVERT_COLS: usize = core::mem::size_of::<ConvertCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertCols<F: Copy> {
    pub values: [ConvertValueCols<F>; NUM_CONVERT_ENTRIES_PER_ROW],
}
const NUM_CONVERT_VALUE_COLS: usize = core::mem::size_of::<ConvertValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertValueCols<F: Copy> {
    pub input: Block<F>,
}

pub const NUM_CONVERT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ConvertPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertPreprocessedCols<F: Copy> {
    pub accesses: [ConvertAccessCols<F>; NUM_CONVERT_ENTRIES_PER_ROW],
}

pub const NUM_CONVERT_ACCESS_COLS: usize = core::mem::size_of::<ConvertAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertAccessCols<F: Copy> {
    pub addrs: [Address<F>; 5],
    pub mults: [F; 5],
}

impl<F: Field> BaseAir<F> for ConvertChip {
    fn width(&self) -> usize {
        NUM_CONVERT_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ConvertChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> &'static str {
        "ExtFeltConvert"
    }

    fn preprocessed_width(&self) -> usize {
        NUM_CONVERT_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::ExtFelt(x) => Some(x),
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
        let nb_rows = instrs_len.div_ceil(NUM_CONVERT_ENTRIES_PER_ROW);
        Some(pad_rows_recursion(nb_rows, height))
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
                Instruction::ExtFelt(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let padded_nb_rows =
            self.preprocessed_num_rows_with_instrs_len(program, instrs.len()).unwrap();

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                padded_nb_rows * NUM_CONVERT_PREPROCESSED_COLS,
            )
        };

        unsafe {
            let padding_start = instrs.len() * NUM_CONVERT_ACCESS_COLS;
            let padding_size = padded_nb_rows * NUM_CONVERT_PREPROCESSED_COLS - padding_start;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_CONVERT_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_CONVERT_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let ExtFeltInstr { addrs, mults, ext2felt } = instr;
                let access: &mut ConvertAccessCols<_> = row.borrow_mut();
                access.addrs = addrs.to_owned();
                if *ext2felt {
                    access.mults[0] = F::one();
                    access.mults[1] = mults[1];
                    access.mults[2] = mults[2];
                    access.mults[3] = mults[3];
                    access.mults[4] = mults[4];
                } else {
                    access.mults[0] = -mults[0];
                    access.mults[1] = -F::one();
                    access.mults[2] = -F::one();
                    access.mults[3] = -F::one();
                    access.mults[4] = -F::one();
                }
            },
        );
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let events = &input.ext_felt_conversion_events;
        let nb_rows = events.len().div_ceil(NUM_CONVERT_ENTRIES_PER_ROW);
        Some(pad_rows_recursion(nb_rows, height))
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
            "generate_trace_into only supports SP1Field"
        );
        let padded_nb_rows = self.num_rows(input).unwrap();
        let events = &input.ext_felt_conversion_events;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_CONVERT_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_CONVERT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_CONVERT_COLS)
        };

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_CONVERT_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_CONVERT_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut ConvertValueCols<_> = row.borrow_mut();
                cols.input = vals.input.to_owned();
            },
        );
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ConvertChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ConvertCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ConvertPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (ConvertValueCols { input }, ConvertAccessCols { addrs, mults }) in
            zip(local.values, prep_local.accesses)
        {
            // First handle the read/write of the extension element.
            // If it's converting extension element to `D` field elements, this is a read.
            // If it's converting `D` field elements to an extension element, this is a write.
            builder.receive_block(addrs[0], input, mults[0]);

            // Handle the read/write of the field element.
            // If it's converting extension element to `D` field elements, this is a write.
            // If it's converting `D` field elements to an extension element, this is a read.
            for i in 0..D {
                builder.send_single(addrs[i + 1], input[i], mults[i + 1]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use slop_matrix::Matrix;
    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::ExecutionRecord;

    use super::ConvertChip;

    use crate::chips::test_fixtures;

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let trace = ConvertChip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let trace = ConvertChip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }
}
