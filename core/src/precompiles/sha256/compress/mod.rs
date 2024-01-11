use p3_field::PrimeField;

use crate::cpu::{air::MemoryAccessCols, MemoryRecord};

mod air;
mod columns;
mod trace;

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone, Copy)]
pub struct ShaCompressEvent {
    pub clk: u32,
    pub w_and_h_ptr: u32,
    pub w: [u32; 64],
    pub h: [u32; 8],
    pub h_read_records: [Option<MemoryRecord>; 8],
    pub h_write_records: [Option<MemoryRecord>; 8],
    pub w_i_read_records: [Option<MemoryRecord>; 64],
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
