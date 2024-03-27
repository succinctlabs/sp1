use core::mem::size_of;

use p3_keccak_air::KeccakCols;
use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

use super::STATE_NUM_WORDS;

#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakMemCols<T> {
    /// Keccak columns from p3_keccak_air.
    pub keccak: KeccakCols<T>,

    pub shard: T,
    pub clk: T,
    pub state_addr: T,

    /// Memory columns for the state.
    pub state_mem: [MemoryReadWriteCols<T>; STATE_NUM_WORDS],

    pub do_memory_check: T,

    pub receive_ecall: T,

    pub is_real: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();
