use std::borrow::BorrowMut;

use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::air::MachineAir;
use sp1_derive::AlignedBorrow;

use crate::{
    instruction::CommitPVHashInstr,
    runtime::{Instruction, RecursionProgram},
    ExecutionRecord,
};

use crate::DIGEST_SIZE;

use super::mem::MemoryAccessCols;

pub const NUM_PUBLIC_VALUES_COLS: usize = core::mem::size_of::<PublicValuesCols<u8>>();
pub const NUM_PUBLIC_VALUES_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PublicValuesPreprocessedCols<u8>>();

#[derive(Default)]
pub struct PublicValuesChip<const DEGREE: usize> {}

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesPreprocessedCols<T: Copy> {
    pub pv_idx: [T; DIGEST_SIZE],
    pub pv_mem: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesCols<T: Copy> {
    pub pv: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for PublicValuesChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for PublicValuesChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "PublicValues".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_PREPROCESSED_COLS]> = Vec::new();
        let commit_pv_hash_instrs = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::CommitPVHash(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        assert!(
            commit_pv_hash_instrs.len() == 1,
            "Expected exactly one CommitPVHash instruction."
        );

        let CommitPVHashInstr { pv_hash_addrs } = commit_pv_hash_instrs[0];
        for (i, addr) in pv_hash_addrs.iter().enumerate() {
            let mut row = [F::zero(); NUM_PUBLIC_VALUES_PREPROCESSED_COLS];
            let cols: &mut PublicValuesPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
            cols.pv_idx[i] = F::one();
            cols.pv_mem = MemoryAccessCols {
                addr: *addr,
                read_mult: F::one(),
                write_mult: F::zero(),
            };
            rows.push(row);
        }

        assert!(rows.len() == DIGEST_SIZE);

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
        );
        Some(trace)
    }
}
