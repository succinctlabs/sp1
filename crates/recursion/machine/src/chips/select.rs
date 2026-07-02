use core::borrow::Borrow;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{Field, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, pad_rows_recursion};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{
    Address, ExecutionRecord, Instruction, RecursionProgram, SelectInstr, SelectIo,
};
use std::{borrow::BorrowMut, mem::MaybeUninit};

use crate::builder::SP1RecursionAirBuilder;

#[derive(Default, Clone)]
pub struct SelectChip;

pub const SELECT_COLS: usize = core::mem::size_of::<SelectCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectCols<F: Copy> {
    pub vals: SelectIo<F>,
}

pub const SELECT_PREPROCESSED_COLS: usize = core::mem::size_of::<SelectPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

impl<F: Field> BaseAir<F> for SelectChip {
    fn width(&self) -> usize {
        SELECT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for SelectChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> &'static str {
        "Select"
    }

    fn preprocessed_width(&self) -> usize {
        SELECT_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Select(x) => Some(x),
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

        let instrs = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Select(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();
        let padded_nb_rows =
            self.preprocessed_num_rows_with_instrs_len(program, instrs.len()).unwrap();

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * SELECT_PREPROCESSED_COLS)
        };

        unsafe {
            let padding_start = instrs.len() * SELECT_PREPROCESSED_COLS;
            let padding_size = padded_nb_rows * SELECT_PREPROCESSED_COLS - padding_start;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * SELECT_PREPROCESSED_COLS;
        values[..populate_len].par_chunks_mut(SELECT_PREPROCESSED_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let SelectInstr { addrs, mult1, mult2 } = instr;
                let access: &mut SelectPreprocessedCols<_> = row.borrow_mut();
                *access = SelectPreprocessedCols {
                    is_real: F::one(),
                    addrs: addrs.to_owned(),
                    mult1: mult1.to_owned(),
                    mult2: mult2.to_owned(),
                };
            },
        );
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let events = &input.select_events;
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
            "generate_trace_into only supports SP1Field"
        );
        let padded_nb_rows = <SelectChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = &input.select_events;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * SELECT_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * SELECT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * SELECT_COLS) };

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * SELECT_COLS;
        values[..populate_len].par_chunks_mut(SELECT_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut SelectCols<_> = row.borrow_mut();
                *cols = SelectCols { vals };
            },
        );
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for SelectChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SelectCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &SelectPreprocessedCols<AB::Var> = (*prep_local).borrow();

        // Receive the selector bit and two input values.
        builder.receive_single(prep_local.addrs.bit, local.vals.bit, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in1, local.vals.in1, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in2, local.vals.in2, prep_local.is_real);

        // Assert that `local.vals.bit` is a boolean value.
        builder.assert_bool(local.vals.bit);

        // If `bit == 1`, then `out1 == in2`. If `bit == 0`, then `out1 == in1`.
        builder.assert_eq(
            local.vals.out1,
            local.vals.in1 + local.vals.bit * (local.vals.in2 - local.vals.in1),
        );
        // If `bit == 1`, then `out2 == in1`. If `bit == 0`, then `out2 == in2`.
        builder.assert_eq(local.vals.out1 + local.vals.out2, local.vals.in1 + local.vals.in2);

        // Send the select result with their respective multiplicity.
        builder.send_single(prep_local.addrs.out1, local.vals.out1, prep_local.mult1);
        builder.send_single(prep_local.addrs.out2, local.vals.out2, prep_local.mult2);
    }
}

#[cfg(test)]
mod tests {
    use crate::{chips::test_fixtures, test::test_recursion_linear_program};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::AbstractField;
    use slop_challenger::IopCtx;
    use sp1_primitives::SP1GlobalContext;
    use sp1_recursion_executor::{instruction as instr, MemAccessKind};

    use super::*;

    #[tokio::test]
    async fn prove_select() {
        type F = <SP1GlobalContext as IopCtx>::F;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let in1: F = rng.sample(rand::distributions::Standard);
                let in2: F = rng.sample(rand::distributions::Standard);
                let bit = F::from_bool(rng.gen_bool(0.5));
                assert_eq!(bit * (bit - F::one()), F::zero());

                let (out1, out2) = if bit == F::one() { (in2, in1) } else { (in1, in2) };
                let alloc_size = 5;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 1, a[0], bit),
                    instr::mem_single(MemAccessKind::Write, 1, a[3], in1),
                    instr::mem_single(MemAccessKind::Write, 1, a[4], in2),
                    instr::select(1, 1, a[0], a[1], a[2], a[3], a[4]),
                    instr::mem_single(MemAccessKind::Read, 1, a[1], out1),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], out2),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        test_recursion_linear_program(instructions).await;
    }

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let trace = SelectChip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let trace = SelectChip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }
}
