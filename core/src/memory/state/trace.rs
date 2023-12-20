use std::borrow::BorrowMut;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{memory::state::air::NUM_MEMORY_STATE_COLS, runtime::Runtime};

use super::{air::MemoryStateCols, MemoryStateChip};

impl MemoryStateChip {
    fn generate_trace_output<F: Field>(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let last_writes = &runtime.last_memory_events;

        let mut rows = last_writes
            .iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_MEMORY_STATE_COLS];

                let cols: &mut MemoryStateCols<F> = row.as_mut_slice().borrow_mut();

                row
            })
            .collect();

        RowMajorMatrix::new(rows, NUM_MEMORY_STATE_COLS)
    }
}
