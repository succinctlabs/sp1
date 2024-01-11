use p3_field::PrimeField;

use crate::cpu::{air::MemoryAccessCols, MemoryRecord};

mod air;
mod columns;
mod trace;

#[derive(Debug, Clone, Copy)]
pub struct ShaCompressEvent {
    pub clk: u32,
    pub w_and_h_ptr: u32,
    pub w: [u32; 64],
    pub h: [u32; 8],
    pub h_read_records: [Option<MemoryRecord>; 8],
    pub h_write_records: [Option<MemoryRecord>; 8],
    pub w_i_records: [Option<MemoryRecord>; 64],
}

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
