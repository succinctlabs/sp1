#![allow(clippy::disallowed_types)]

//! SP1's degree-3 Keccak-f trace representation.
//!
//! The theta/post-theta layout comes from the certified `keccak.fast` AIR.
//! SP1 additionally materializes theta parities and interaction limbs because
//! its machine backend requires degree-3 constraints and affine interactions.

mod columns;
mod constants;
mod generation;

pub use columns::*;
pub use generation::*;

pub const NUM_ROUNDS: usize = 24;
pub const U64_LIMBS: usize = 4;
pub const RC_BIT_POSITIONS: [usize; 7] = [0, 1, 3, 7, 15, 31, 63];

const BITS_PER_LIMB: usize = 16;
