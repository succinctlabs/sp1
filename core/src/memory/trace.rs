use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use alloc::collections::BTreeSet;

use super::MemoryEvent;

#[derive(Debug, Clone)]
pub struct MemoryTable<T>(pub RowMajorMatrix<T>);

impl<F: PrimeField> MemoryTable<F> {
    pub fn generate(events: &[MemoryEvent]) -> Self {
        let mut event_map = events.into_iter().collect::<BTreeSet<_>>();
        todo!()
    }
}
