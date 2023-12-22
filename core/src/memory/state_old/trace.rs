use std::borrow::BorrowMut;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::{Bool, Word},
    memory::{state_old::air::NUM_MEMORY_STATE_COLS, MemOp},
    runtime::Runtime,
};

use super::{air::MemoryStateCols, MemoryStateChip};

impl MemoryStateChip {
    pub fn generate_trace_output<F: Field>(runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let last_writes = &runtime.last_memory_events;

        let mut rows = last_writes
            .iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_MEMORY_STATE_COLS];

                let cols: &mut MemoryStateCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = F::from_canonical_u32(event.clk);
                cols.addr = Word::from(event.addr);
                cols.value = Word::from(event.value);
                cols.is_read = Bool::from(event.op == MemOp::Read);
                cols.is_real = Bool::from(true);

                row
            })
            .collect::<Vec<_>>();

        let dummy_len = last_writes.len().next_power_of_two() - last_writes.len();
        let dummy_rows = (0..dummy_len).flat_map(|_| [F::zero(); NUM_MEMORY_STATE_COLS]);

        rows.extend(dummy_rows);

        RowMajorMatrix::new(rows, NUM_MEMORY_STATE_COLS)
    }
}
