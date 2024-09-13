use core::mem::size_of;

use p3_keccak_air::KeccakCols;
use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

use super::STATE_NUM_WORDS;

/// KeccakMemCols is the column layout for the keccak permutation.
///
/// The columns defined in the `p3_keccak_air` crate are embedded here as `keccak`. Other columns
/// are used to track the VM context.
#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakMemCols<T> {
    /// Keccak columns from p3_keccak_air. Note it is assumed in trace gen to be the first field.
    pub keccak: KeccakCols<T>,

    pub shard: T,
    pub clk: T,
    pub nonce: T,
    pub state_addr: T,

    /// Memory columns for the state.
    pub state_mem: [MemoryReadWriteCols<T>; STATE_NUM_WORDS],

    // If row is real and first or last cycle of 24-cycle
    pub do_memory_check: T,

    // If row is real and first cycle of 24-cycle
    pub receive_ecall: T,

    pub is_real: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();
