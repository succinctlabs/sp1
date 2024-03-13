mod bigint_ops;

pub use bigint_ops::*;

use num::{BigUint, One};
use serde::{Deserialize, Serialize};

use crate::{operations::field::params::NB_BITS_PER_LIMB, utils::ec::field::FieldParameters};

/// Number of `u8` limbs in a bigint.
const NUM_LIMBS_IN_BIGINT: usize = 32;

/// Number of `u32` WORDS in a bigint.
const NUM_WORDS_IN_BIGINT: usize = NUM_LIMBS_IN_BIGINT / 4;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct U256Field;

impl FieldParameters for U256Field {
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = NUM_LIMBS_IN_BIGINT;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const MODULUS: [u8; NUM_LIMBS_IN_BIGINT] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    const WITNESS_OFFSET: usize = 1usize << 13;

    fn modulus() -> BigUint {
        (BigUint::one() << 256) - BigUint::one()
    }

    fn nb_bits() -> usize {
        Self::NB_BITS_PER_LIMB * Self::NB_LIMBS
    }
}
