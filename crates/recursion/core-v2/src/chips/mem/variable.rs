use core::borrow::Borrow;
use instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr};
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use sp1_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use std::{borrow::BorrowMut, iter::zip, marker::PhantomData};

use crate::{builder::SP1RecursionAirBuilder, *};

use super::{MemoryAccessCols, NUM_MEM_ACCESS_COLS};

pub const NUM_VAR_MEM_ENTRIES_PER_ROW: usize = 2;

#[derive(Default)]
pub struct MemoryChip<F> {
    _marker: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<F: Copy> {
    values: [Block<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryPreprocessedCols<F: Copy> {
    accesses: [MemoryAccessCols<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}

impl<F: Send + Sync> BaseAir<F> for MemoryChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryChip<F> {
    type Record = crate::ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryVar".to_string()
    }
    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let accesses = program
            .instructions
            .par_iter() // Using `rayon` here provides a big speedup.
            .flat_map_iter(|instruction| match instruction {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                _ => vec![],
            })
            .collect::<Vec<_>>();

        let nb_rows = accesses.len().div_ceil(NUM_VAR_MEM_ENTRIES_PER_ROW);
        let padded_nb_rows = match program.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = accesses.len() * NUM_MEM_ACCESS_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_MEM_ACCESS_COLS)
            .zip_eq(accesses)
            .for_each(|(row, &(addr, mult))| *row.borrow_mut() = MemoryAccessCols { addr, mult });

        Some(RowMajorMatrix::new(values, NUM_MEM_PREPROCESSED_INIT_COLS))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let mut rows = input
            .mem_var_events
            .chunks(NUM_VAR_MEM_ENTRIES_PER_ROW)
            .map(|row_events| {
                let mut row = [F::zero(); NUM_MEM_INIT_COLS];
                let cols: &mut MemoryCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, vals) in zip(&mut cols.values, row_events) {
                    *cell = vals.inner;
                }
                row
            })
            .collect::<Vec<_>>();

        // Pad the rows to the next power of two.
        pad_rows_fixed(&mut rows, || [F::zero(); NUM_MEM_INIT_COLS], input.fixed_log2_rows(self));

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MEM_INIT_COLS)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MemoryChip<AB::F>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (value, access) in zip(local.values, prep_local.accesses) {
            builder.send_block(access.addr, value, access.mult);
        }
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    pub fn generate_trace() {
        let shard = ExecutionRecord::<BabyBear> {
            mem_var_events: vec![
                MemEvent { inner: BabyBear::one().into() },
                MemEvent { inner: BabyBear::one().into() },
            ],
            ..Default::default()
        };
        let chip = MemoryChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn prove_basic_mem() {
        let program = RecursionProgram {
            instructions: vec![
                instr::mem(MemAccessKind::Write, 1, 1, 2),
                instr::mem(MemAccessKind::Read, 1, 1, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machines(program);
    }

    #[test]
    #[should_panic]
    pub fn basic_mem_bad_mult() {
        let program = RecursionProgram {
            instructions: vec![
                instr::mem(MemAccessKind::Write, 1, 1, 2),
                instr::mem(MemAccessKind::Read, 999, 1, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machines(program);
    }

    #[test]
    #[should_panic]
    pub fn basic_mem_bad_address() {
        let program = RecursionProgram {
            instructions: vec![
                instr::mem(MemAccessKind::Write, 1, 1, 2),
                instr::mem(MemAccessKind::Read, 1, 999, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machines(program);
    }

    #[test]
    #[should_panic]
    pub fn basic_mem_bad_value() {
        let program = RecursionProgram {
            instructions: vec![
                instr::mem(MemAccessKind::Write, 1, 1, 2),
                instr::mem(MemAccessKind::Read, 1, 1, 999),
            ],
            ..Default::default()
        };

        run_recursion_test_machines(program);
    }
}
