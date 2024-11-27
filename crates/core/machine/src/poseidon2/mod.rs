pub mod air;
pub mod columns;

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
