use core::borrow::Borrow;
use itertools::Itertools;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, pad_rows_recursion};
use sp1_recursion_executor::{
    Block, ExecutionRecord, Instruction, MemAccessKind, MemInstr, RecursionProgram,
};
use std::{borrow::BorrowMut, iter::zip, marker::PhantomData, mem::MaybeUninit};

use crate::builder::SP1RecursionAirBuilder;

use super::MemoryAccessCols;

pub const NUM_CONST_MEM_ENTRIES_PER_ROW: usize = 1;

#[derive(Default, Clone)]
pub struct MemoryConstChip<F> {
    _marker: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryConstCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryConstCols<F: Copy> {
    // At least one column is required, otherwise a bunch of things break.
    _nothing: F,
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryConstPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryConstPreprocessedCols<F: Copy> {
    values_and_accesses: [(Block<F>, MemoryAccessCols<F>); NUM_CONST_MEM_ENTRIES_PER_ROW],
}
impl<F: Send + Sync> BaseAir<F> for MemoryConstChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryConstChip<F> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> &'static str {
        "MemoryConst"
    }
    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Mem(MemInstr { addrs, vals, mult, kind }) => {
                    let mult = mult.to_owned();
                    let mult = match kind {
                        MemAccessKind::Read => -mult,
                        MemAccessKind::Write => mult,
                    };

                    Some((vals.inner, MemoryAccessCols { addr: addrs.inner, mult }))
                }
                _ => None,
            })
            .chunks(NUM_CONST_MEM_ENTRIES_PER_ROW)
            .into_iter()
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
        let chunks = program
            .inner
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::Mem(MemInstr { addrs, vals, mult, kind }) => {
                    let mult = mult.to_owned();
                    let mult = match kind {
                        MemAccessKind::Read => -mult,
                        MemAccessKind::Write => mult,
                    };

                    Some((vals.inner, MemoryAccessCols { addr: addrs.inner, mult }))
                }
                _ => None,
            })
            .chunks(NUM_CONST_MEM_ENTRIES_PER_ROW);

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;

        let mut nb_rows = 0;
        for row_vs_as in &chunks {
            let start = nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS;
            let values = unsafe {
                core::slice::from_raw_parts_mut(
                    buffer_ptr.add(start),
                    NUM_MEM_PREPROCESSED_INIT_COLS,
                )
            };
            let cols: &mut MemoryConstPreprocessedCols<_> = values.borrow_mut();
            for (cell, access) in zip(&mut cols.values_and_accesses, row_vs_as) {
                *cell = access;
            }
            nb_rows += 1;
        }

        let padded_nb_rows = self.preprocessed_num_rows_with_instrs_len(program, nb_rows).unwrap();

        // NOTE: this is safe since there are always a single event per row.
        unsafe {
            let padding_start = nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS;
            let padding_size = padded_nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS - padding_start;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let num_rows = input.mem_const_count.div_ceil(NUM_CONST_MEM_ENTRIES_PER_ROW);
        let padded_nb_rows = pad_rows_recursion(num_rows, height);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = self.num_rows(input).unwrap();
        unsafe {
            core::ptr::write_bytes(buffer.as_mut_ptr(), 0, padded_nb_rows);
        }
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MemoryConstChip<AB::F>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryConstPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (value, access) in prep_local.values_and_accesses {
            builder.send_block(access.addr, value, access.mult);
        }
    }
}

#[cfg(test)]
mod tests {
    use slop_matrix::Matrix;
    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::{instruction as instr, ExecutionRecord, MemAccessKind};

    use super::MemoryConstChip;

    use crate::{chips::test_fixtures, test::test_recursion_linear_program};

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let chip = MemoryConstChip::default();
        let trace = chip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let chip = MemoryConstChip::default();
        let trace = chip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    pub async fn prove_basic_mem() {
        test_recursion_linear_program(vec![
            instr::mem(MemAccessKind::Write, 1, 1, 2),
            instr::mem(MemAccessKind::Read, 1, 1, 2),
        ])
        .await;
    }

    #[tokio::test]
    #[should_panic]
    pub async fn basic_mem_bad_mult() {
        test_recursion_linear_program(vec![
            instr::mem(MemAccessKind::Write, 1, 1, 2),
            instr::mem(MemAccessKind::Read, 9, 1, 2),
        ])
        .await;
    }

    #[tokio::test]
    #[should_panic]
    pub async fn basic_mem_bad_address() {
        test_recursion_linear_program(vec![
            instr::mem(MemAccessKind::Write, 1, 1, 2),
            instr::mem(MemAccessKind::Read, 1, 9, 2),
        ])
        .await;
    }

    #[tokio::test]
    #[should_panic]
    pub async fn basic_mem_bad_value() {
        test_recursion_linear_program(vec![
            instr::mem(MemAccessKind::Write, 1, 1, 2),
            instr::mem(MemAccessKind::Read, 1, 1, 999),
        ])
        .await;
    }
}
