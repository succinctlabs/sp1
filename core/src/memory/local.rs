use std::{borrow::BorrowMut, mem::size_of};

use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;

use crate::{
    air::MachineAir,
    runtime::{ExecutionRecord, Program},
    stark::SP1AirBuilder,
    utils::pad_rows_fixed,
};

pub(crate) const NUM_MEMORY_LOCAL_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MemoryLocalEvent {
    pub addr: u32,
    pub value: u32,
    pub timestamp: u32,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// Value of the memory access.
    pub value: T,
}

#[derive(Default)]
/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryLocalChip {}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows: Vec<[F; NUM_MEMORY_LOCAL_COLS]> = Vec::new();

        input.memory_records.iter().for_each(|mem_record| {
            let mut row = [F::zero(); NUM_MEMORY_LOCAL_COLS];
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();

            cols.timestamp = F::from_canonical_u32(mem_record.timestamp);
            cols.addr = F::from_canonical_u32(mem_record.addr);
            cols.value = F::from_canonical_u32(mem_record.value);

            rows.push(row);
        });

        pad_rows_fixed(&mut rows, || [F::zero(); NUM_MEMORY_LOCAL_COLS], None);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MEMORY_LOCAL_COLS)
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.memory_records.is_empty()
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, _builder: &mut AB) {}
}
