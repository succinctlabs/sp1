mod air;
mod columns;
mod execute;
mod flags;
mod trace;

pub use columns::*;

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha512ExtendEvent {
    pub shard: u32,
    pub clk: u32,
    pub w_ptr: u32,
    pub w_i_minus_15_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_2_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_16_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_7_reads: Vec<MemoryReadRecord>,
    pub w_i_writes: Vec<MemoryWriteRecord>,
}

/// Implements the SHA-512 extension operation which loops over i = [16, 79] and modifies w[i] in each
/// iteration. The only input to the syscall is the 4byte-aligned pointer to the w array.
///
/// In the AIR, each SHA extend syscall takes up 48 rows, where each row corresponds to a single
/// iteration of the loop.
#[derive(Default)]
pub struct Sha512ExtendChip;

impl ShaExtendChip {
    pub fn new() -> Self {
        Self {}
    }
}

pub fn sha_extend(w: &mut [u64]) {
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}
