mod external;
mod pure;

pub use external::*;
pub use pure::*;

/// The number of external rounds in the Poseidon permutation.
pub(crate) const ROUNDS_F: usize = 8;

/// The number of internal rounds in the Poseidon permutation.
pub(crate) const ROUNDS_P: usize = 22;

/// The total number of rounds in the Poseidon permutation.
pub(crate) const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

/// The number of initial number of external rounds in the Poseidon permutation.
pub(crate) const ROUNDS_F_BEGINNING: usize = ROUNDS_F / 2;

/// The round till the internal rounds ends.
pub(crate) const P_END: usize = ROUNDS_F_BEGINNING + ROUNDS_P;

// TODO: Make this public inside Plonky3 and import directly.
pub const MATRIX_DIAG_16_BABYBEAR_U32: [u32; 16] = [
    0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b, 0x258c2e8b,
    0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda, 0x27705c83, 0x5231c802,
];
