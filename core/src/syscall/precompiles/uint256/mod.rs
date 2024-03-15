mod uint256_mul;

pub use uint256_mul::*;

use crate::{
    operations::field::params::{NB_BITS_PER_LIMB, NUM_LIMBS},
    utils::ec::field::FieldParameters,
};
use num::{BigUint, One};
use serde::{Deserialize, Serialize};

/// Number of `u32` WORDS in a uint256.
const NUM_WORDS_IN_UINT256: usize = NUM_LIMBS / 4;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct U256Field;

impl FieldParameters for U256Field {
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = NUM_LIMBS;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const MODULUS: [u8; NUM_LIMBS] = [
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

#[cfg(test)]
mod tests {

    use crate::{
        utils::{self, tests::UINT256_MUL},
        SP1Prover, SP1Stdin,
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        SP1Prover::prove(UINT256_MUL, SP1Stdin::new()).unwrap();
    }
}
