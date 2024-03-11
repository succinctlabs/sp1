mod ed_add;
mod ed_decompress;

pub use ed_add::*;
pub use ed_decompress::*;

// The number of limbs in the field representation.
const NUM_LIMBS: usize = 32;

/// The number of `u8` witness limbs in the field representation.
const NUM_WITNESS_LIMBS: usize = 2 * NUM_LIMBS - 2;
