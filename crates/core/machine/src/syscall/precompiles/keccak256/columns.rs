use core::mem::size_of;
use slop_keccak_air::KeccakCols;
use sp1_derive::AlignedBorrow;

/// KeccakMemCols is the column layout for the keccak permutation.
///
/// The columns defined in the `slop_keccak_air` crate are embedded here as `keccak`. Other columns
/// are used to track the VM context.
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct KeccakMemCols<T> {
    /// Keccak columns from slop_keccak_air. Note it is assumed in trace gen to be the first field.
    pub keccak: KeccakCols<T>,
    pub clk_high: T,
    pub clk_low: T,
    pub state_addr: [T; 3],
    pub index: T,
    pub is_real: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();

static_assertions::const_assert_eq!(NUM_KECCAK_MEM_COLS, 2_478);
