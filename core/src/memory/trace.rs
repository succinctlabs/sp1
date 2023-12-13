use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use super::{air::MemoryAir, MemoryEvent};

impl MemoryAir {
    pub fn generate_trace<F: PrimeField>(events: &mut [MemoryEvent]) -> RowMajorMatrix<F> {
        // Sort the events by address and then by clock cycle.
        events.sort_by_key(|event| (event.addr, event.clk, event.op));
        todo!()
    }
}
