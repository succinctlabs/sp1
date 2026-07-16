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

/// Witgen inputs for ONE `KeccakPermute` row (one round of one permutation): one
/// `#[repr(C)]` row per (event, round). The chip has no core-machine witgen fn (its
/// op-DAG is recorded inline on the GPU side — see `record_keccak_program` in
/// sp1-gpu tracegen); the GPU packs 24 of these per event (replaying the
/// permutation host-side so every row carries its own 25-lane round-input state)
/// and the recorder casts a wire slice to the same struct (see
/// `record_witgen_inputs`), so field order IS the kernel input layout.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct KeccakWitgenInput<T> {
    /// The permutation's 25 preimage lanes (y-major: `state[y * 5 + x]`).
    pub preimage: [T; 25],
    /// The round's 25 input lanes (the state after `round` rounds).
    pub a: [T; 25],
    /// The round index `∈ 0..24`.
    pub round: T,
    /// The `index` column value (equals `round` on real rows, 0 on dummy rows).
    pub index: T,
    /// The round constant `RC[round]`.
    pub rc: T,
    pub clk: T,
    pub state_addr: T,
    pub is_real: T,
}

/// Number of witgen inputs per `KeccakPermute` row.
pub const NUM_KECCAK_WITGEN_INPUTS: usize = size_of::<KeccakWitgenInput<u8>>();
