use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::{dense::RowMajorMatrix, MatrixRowSlices};
use sp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, SP1AirBuilder, SubAirBuilder, WordAirBuilder},
    operations::IsZeroOperation,
    runtime::ExecutionRecord,
    utils::pad_to_power_of_two,
};

use super::{MemoryChipKind, MemoryGlobalChip, MemoryInitCols, NUM_MEMORY_INIT_COLS};

use core::mem::size_of;
use std::borrow::{Borrow, BorrowMut};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitExtendedCols<T> {
    pub mem_cols: MemoryInitCols<T>,
    pub addr_is_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_MEMORY_INIT_EXTENDED_COLS: usize = size_of::<MemoryInitExtendedCols<u8>>();

pub struct MemoryGlobalInitChip {
    memory_global_chip: MemoryGlobalChip,
}

impl MemoryGlobalInitChip {
    pub fn new() -> Self {
        let memory_global_chip = MemoryGlobalChip::new(MemoryChipKind::Init);
        Self { memory_global_chip }
    }
}

impl<F> BaseAir<F> for MemoryGlobalInitChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_EXTENDED_COLS
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryGlobalInitChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "MemoryInitialize".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = (0..input.first_memory_record.len()) // TODO: change this back to par_iter
            .map(|i| {
                let mut row = [F::zero(); NUM_MEMORY_INIT_EXTENDED_COLS];
                let mem_record = MemoryInitCols::generate_trace_row(
                    input.first_memory_record[i].0,
                    &input.first_memory_record[i].1,
                    input.first_memory_record[i].2,
                );
                row[0..NUM_MEMORY_INIT_COLS].copy_from_slice(&mem_record);

                let cols: &mut MemoryInitExtendedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr_is_zero.populate(input.first_memory_record[i].0);

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_EXTENDED_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_EXTENDED_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.first_memory_record.is_empty()
    }
}

impl<AB> Air<AB> for MemoryGlobalInitChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitExtendedCols<AB::Var> = main.row_slice(0).borrow();

        let mut sub_builder =
            SubAirBuilder::<AB, MemoryGlobalChip, AB::Var>::new(builder, 0..NUM_MEMORY_INIT_COLS);

        // Eval the plonky3 keccak air
        self.memory_global_chip.eval(&mut sub_builder);

        builder.assert_word_zero(local.mem_cols.value);

        builder
            .when(local.addr_is_zero.result)
            .assert_word_zero(local.mem_cols.value);
    }
}
