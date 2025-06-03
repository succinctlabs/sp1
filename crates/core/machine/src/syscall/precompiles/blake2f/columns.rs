use sp1_derive::AlignedBorrow;

pub const NUM_BLAKE2F_COMPRESS_COLS: usize = size_of::<Blake2fCompressColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct  Blake2fCompressColumns<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub w_ptr: T,
    /// Final block flag (used as a selector/flag in AIR)
    pub f_flag: T,
}