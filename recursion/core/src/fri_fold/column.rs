use core::mem::size_of;
use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

/// The number of main trace columns for `Poseidon2Chip`.
pub const NUM_FRI_FOLD_COLS: usize = size_of::<FriFoldCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone)]
#[repr(C)]
pub struct FriFoldCols<T> {
    pub clk: T,

    /// The parameters into the FRI fold precompile.  These values are only read from memory.
    pub m: MemoryReadWriteCols<T>,
    pub input_ptr: MemoryReadWriteCols<T>,

    /// The inputs stored in memory.  All the values are just read from memory.
    pub z: MemoryReadWriteCols<T>,
    pub alpha: MemoryReadWriteCols<T>,
    pub x: MemoryReadWriteCols<T>,
    pub log_height: MemoryReadWriteCols<T>,
    pub mat_opening_ptr: MemoryReadWriteCols<T>,
    pub ps_at_z_ptr: MemoryReadWriteCols<T>,
    pub alpha_pow_ptr: MemoryReadWriteCols<T>,
    pub ro_ptr: MemoryReadWriteCols<T>,

    pub p_at_x: MemoryReadWriteCols<T>,
    pub p_at_z: MemoryReadWriteCols<T>,

    /// The values here are read and then written.
    pub alpha_pow_at_log_height: MemoryReadWriteCols<T>,
    pub ro_at_log_height: MemoryReadWriteCols<T>,
}
