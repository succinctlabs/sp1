use std::borrow::{Borrow, BorrowMut};

use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;

use crate::air::SP1RecursionAirBuilder;
use crate::fri_fold::{FriFoldChip, FriFoldCols};
use crate::poseidon2::external::Poseidon2Cols;
use crate::poseidon2::Poseidon2Chip;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_MULTI_COLS: usize = core::mem::size_of::<MultiCols<u8>>();

#[derive(Default)]
pub struct MultiChip {
    pub fixed_log2_rows: Option<usize>,
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct MultiCols<T: Copy> {
    pub instruction: InstructionSpecificCols<T>,
    pub is_fri_fold: T,
    pub is_poseidon2: T,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union InstructionSpecificCols<T: Copy> {
    fri_fold: FriFoldCols<T>,
    poseidon2: Poseidon2Cols<T>,
}

impl<F> BaseAir<F> for MultiChip {
    fn width(&self) -> usize {
        NUM_MULTI_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MultiChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Multi".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let fri_fold_chip = FriFoldChip::default();
        let poseidon2 = Poseidon2Chip::default();
        let fri_fold_trace = fri_fold_chip.generate_trace(input, output);
        let mut poseidon2_trace = poseidon2.generate_trace(input, output);

        let mut rows = fri_fold_trace
            .clone()
            .rows_mut()
            .chain(poseidon2_trace.rows_mut())
            .enumerate()
            .map(|(i, instruction_row)| {
                let mut row = [F::zero(); NUM_MULTI_COLS];
                row[0..instruction_row.len()].copy_from_slice(instruction_row);
                let cols: &mut MultiCols<F> = row.as_mut_slice().borrow_mut();
                if i < fri_fold_trace.height() {
                    cols.is_fri_fold = F::one();
                } else {
                    let cols: &mut MultiCols<F> = row.as_mut_slice().borrow_mut();
                    cols.is_poseidon2 = F::one();
                }
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MULTI_COLS],
            self.fixed_log2_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MULTI_COLS)
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MultiChip
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &MultiCols<AB::Var> = (*local).borrow();
        let next: &MultiCols<AB::Var> = (*next).borrow();

        let fri_fold_chip = FriFoldChip::default();
        let mut sub_builder = builder.when(local.is_fri_fold);
        fri_fold_chip.eval_fri_fold(
            &mut sub_builder,
            local.fri_fold(),
            next.fri_fold(),
            AB::Expr::one() - next.is_fri_fold,
        );

        let poseidon2_chip = Poseidon2Chip::default();
        let mut sub_builder = builder.when(local.is_poseidon2);
        poseidon2_chip.eval_poseidon2(&mut sub_builder, local.poseidon2());
    }
}
// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> MultiCols<T> {
    pub fn fri_fold(&self) -> &FriFoldCols<T> {
        unsafe { &self.instruction.fri_fold }
    }

    pub fn poseidon2(&self) -> &Poseidon2Cols<T> {
        unsafe { &self.instruction.poseidon2 }
    }
}
