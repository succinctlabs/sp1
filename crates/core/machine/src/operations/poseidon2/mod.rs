use permutation::Poseidon2Degree3Cols;
use sp1_derive::AlignedBorrow;

pub mod air;
pub mod permutation;
pub mod trace;

/// The width of the permutation.
pub const WIDTH: usize = 16;

/// The rate of the permutation.
pub const RATE: usize = WIDTH / 2;

/// The number of external rounds.
pub const NUM_EXTERNAL_ROUNDS: usize = 8;

/// The number of internal rounds.
pub const NUM_INTERNAL_ROUNDS: usize = 13;

/// The total number of rounds.
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// The number of columns in the Poseidon2 operation.
pub const NUM_POSEIDON2_OPERATION_COLUMNS: usize = std::mem::size_of::<Poseidon2Operation<u8>>();

/// A set of columns needed to compute the Poseidon2 operation.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Operation<T: Copy> {
    /// The permutation.
    pub permutation: Poseidon2Degree3Cols<T>,
}
