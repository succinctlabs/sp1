use p3_field::PrimeField;

use crate::cpu::{air::MemoryAccessCols, MemoryRecord};

mod air;
mod columns;
mod trace;

pub struct ShaCompressChip;

impl ShaCompressChip {
    pub fn new() -> Self {
        Self {}
    }

    fn populate_access<F: PrimeField>(
        &self,
        cols: &mut MemoryAccessCols<F>,
        value: u32,
        record: Option<MemoryRecord>,
    ) {
        cols.value = value.into();
        // If `imm_b` or `imm_c` is set, then the record won't exist since we're not accessing from memory.
        if let Some(record) = record {
            cols.prev_value = record.value.into();
            cols.segment = F::from_canonical_u32(record.segment);
            cols.timestamp = F::from_canonical_u32(record.timestamp);
        }
    }
}
