mod weierstrass_add;
mod weierstrass_double;

pub use weierstrass_add::*;
pub use weierstrass_double::*;

// The number of `u8` limbs in the field representation.
const NUM_LIMBS: usize = 32;

/// The number of `u8` witness limbs in the field representation.
const NUM_WITNESS_LIMBS: usize = 2 * NUM_LIMBS - 2;
