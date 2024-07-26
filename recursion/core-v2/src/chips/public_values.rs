use std::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core::air::MachineAir;
use sp1_derive::AlignedBorrow;

use crate::{
    builder::SP1RecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    CommitPVHashInstr, ExecutionRecord,
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
    pub pv_element: T,
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

        let CommitPVHashInstr { pv_addrs } = commit_pv_hash_instrs[0];
        for (i, addr) in pv_addrs.iter().enumerate() {
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

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        assert!(input.commit_pv_hash_events.len() == 1);

        let mut rows = [F::zero(); NUM_PUBLIC_VALUES_COLS * DIGEST_SIZE];
        for (i, event) in input.commit_pv_hash_events[0].pv_hash.iter().enumerate() {
            rows[i] = *event;
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.to_vec(), NUM_PUBLIC_VALUES_COLS)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB, const DEGREE: usize> Air<AB> for PublicValuesChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PublicValuesCols<AB::Var> = (*local).borrow();
        let prepr = builder.preprocessed();
        let local_prepr = prepr.row_slice(0);
        let local_prepr: &PublicValuesPreprocessedCols<AB::Var> = (*local_prepr).borrow();
        let pv = builder.public_values();
        let pv_elms: [AB::Expr; DIGEST_SIZE] = core::array::from_fn(|i| pv[i].into());

        // Constrain mem read for the public value element.
        builder.receive_single(
            local_prepr.pv_mem.addr,
            local.pv_element,
            local_prepr.pv_mem.read_mult,
        );

        for i in 0..DIGEST_SIZE {
            // Ensure that the public value element is the same for all rows within a fri fold invocation.
            builder
                .when(local_prepr.pv_idx[i])
                .assert_eq(pv_elms[i].clone(), local.pv_element);
        }
    }
}
