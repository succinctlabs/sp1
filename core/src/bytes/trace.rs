use std::collections::BTreeMap;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    bytes::{air::NUM_BYTE_COLS, NUM_BYTE_OPS},
    runtime::Runtime,
};

use super::{ByteChip, ByteLookupEvent};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> ByteChip<F> {
    pub(crate) fn generate_trace_from_evenets(
        &self,
        byte_lookups: &BTreeMap<ByteLookupEvent, usize>,
    ) -> RowMajorMatrix<F> {
        let mut multiplicities = vec![0; NUM_ROWS * NUM_BYTE_OPS];

        for (lookup, mult) in byte_lookups.iter() {
            let (row, index) = self.table_map[lookup];

            multiplicities[row * NUM_BYTE_COLS + index] = *mult;
        }
        todo!()
    }
}
