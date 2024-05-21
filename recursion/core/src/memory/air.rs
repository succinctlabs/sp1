use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::air::{AirInteraction, SP1AirBuilder};
use sp1_core::lookup::InteractionKind;
use sp1_core::utils::pad_rows_fixed;
use std::borrow::{Borrow, BorrowMut};
use tracing::instrument;

use super::columns::MemoryInitCols;
use crate::memory::MemoryGlobalChip;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

#[allow(dead_code)]
impl MemoryGlobalChip {
    pub fn new() -> Self {
        Self {
            fixed_log2_rows: None,
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryGlobalChip {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryGlobalChip".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate memory trace", level = "debug", skip_all, fields(first_rows = input.first_memory_record.len(), last_rows = input.last_memory_record.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        // Fill in the initial memory records.
        rows.extend(
            input
                .first_memory_record
                .iter()
                .map(|(addr, value)| {
                    let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                    let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                    cols.addr = *addr;
                    cols.timestamp = F::zero();
                    cols.value = *value;
                    cols.is_initialize = F::one();
                    row
                })
                .collect::<Vec<_>>(),
        );

        // Fill in the finalize memory records.
        rows.extend(
            input
                .last_memory_record
                .iter()
                .map(|(addr, timestamp, value)| {
                    let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                    let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                    cols.addr = *addr;
                    cols.timestamp = *timestamp;
                    cols.value = *value;
                    cols.is_finalize = F::one();
                    row
                })
                .collect::<Vec<_>>(),
        );

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MEMORY_INIT_COLS],
            self.fixed_log2_rows,
        );

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.first_memory_record.is_empty() || !shard.last_memory_record.is_empty()
    }
}

impl<F> BaseAir<F> for MemoryGlobalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        // Verify that is_initialize and is_finalize are bool and that at most one is true.
        builder.assert_bool(local.is_initialize);
        builder.assert_bool(local.is_finalize);
        builder.assert_bool(local.is_initialize + local.is_finalize);

        builder.send(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_initialize.into(),
            InteractionKind::Memory,
        ));
        builder.receive(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_finalize.into(),
            InteractionKind::Memory,
        ));
    }
}
