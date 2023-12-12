use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use super::MemoryEvent;

#[derive(Debug, Clone)]
pub struct MemoryTable<T>(pub RowMajorMatrix<T>);

impl<F: PrimeField> MemoryTable<F> {
    pub fn generate(events: &mut [MemoryEvent]) -> Self {
        // Sort the events by address and then by clock cycle.
        events.sort_by_key(|event| (event.addr, event.clk));
        todo!()
    }
}
