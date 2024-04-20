use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{AirInteraction, SP1AirBuilder};
use sp1_core::lookup::InteractionKind;
use sp1_core::{air::MachineAir, utils::pad_to_power_of_two};
use std::borrow::{Borrow, BorrowMut};

use super::columns::FriFoldCols;
use super::FriFoldEvent;
use crate::air::Block;
use crate::memory::MemoryChipKind;
use crate::memory::MemoryGlobalChip;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub(crate) const NUM_FRI_FOLD_COLS: usize = size_of::<FriFoldCols<u8>>();

pub struct FriFoldChip {}

impl<F: PrimeField32> MachineAir<F> for FriFoldChip {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    #[allow(unused_variables)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let events = [FriFoldEvent {}];
        let rows = events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FRI_FOLD_COLS];
                let cols: &mut FriFoldCols<F> = row.as_mut_slice().borrow_mut();
                cols.populate(event);
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRI_FOLD_COLS,
        );

        pad_to_power_of_two::<NUM_FRI_FOLD_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for FriFoldChip {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<AB> Air<AB> for FriFoldChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FriFoldCols<AB::Var> = (*local).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );
    }
}
