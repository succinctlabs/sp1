use core::borrow::Borrow;
use instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr};
use itertools::Itertools;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use std::{borrow::BorrowMut, iter::zip, marker::PhantomData};

use crate::{builder::SP1RecursionAirBuilder, *};

use super::MemoryAccessCols;

pub const NUM_MEM_ENTRIES_PER_ROW: usize = 16;

#[derive(Default)]
pub struct MemoryChip<F> {
    _data: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<F: Copy> {
    values: [Block<F>; NUM_MEM_ENTRIES_PER_ROW],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryPreprocessedCols<F: Copy> {
    accesses: [MemoryAccessCols<F>; NUM_MEM_ENTRIES_PER_ROW],
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
        let rows = program
            .instructions
            .iter()
            .flat_map(|instruction| match instruction {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults
                    .iter()
                    .map(|&(addr, mult)| MemoryAccessCols { addr, mult })
                    .collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults
                    .iter()
                    .map(|&(addr, mult)| MemoryAccessCols { addr, mult })
                    .collect(),

                _ => vec![],
            })
            .chunks(NUM_MEM_ENTRIES_PER_ROW)
            .into_iter()
            .map(|row_accesses| {
                let mut row = [F::zero(); NUM_MEM_PREPROCESSED_INIT_COLS];
                let cols: &mut MemoryPreprocessedCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, access) in zip(&mut cols.accesses, row_accesses) {
                    *cell = access;
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEM_PREPROCESSED_INIT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEM_PREPROCESSED_INIT_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = input
            .mem_var_events
            .chunks(NUM_MEM_ENTRIES_PER_ROW)
            .map(|row_events| {
                let mut row = [F::zero(); NUM_MEM_INIT_COLS];
                let cols: &mut MemoryCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, vals) in zip(&mut cols.values, row_events) {
                    *cell = vals.inner;
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MEM_INIT_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEM_INIT_COLS, F>(&mut trace.values);

        trace
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
