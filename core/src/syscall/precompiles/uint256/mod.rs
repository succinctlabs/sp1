mod uint256_mul;

use typenum::{U32, U62};
pub use uint256_mul::*;

use crate::utils::ec::field::{FieldParameters, NumLimbs};
use num::{BigUint, One};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct U256Field;

impl FieldParameters for U256Field {
    const MODULUS: &'static [u8] = &[
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    const WITNESS_OFFSET: usize = 1usize << 13;

    fn modulus() -> BigUint {
        (BigUint::one() << 256) - BigUint::one()
    }
}

impl NumLimbs for U256Field {
    type Limbs = U32;
    type Witness = U62;
}

#[cfg(test)]
mod tests {

    use crate::{
        utils::{
            self,
            tests::{UINT256_DIV, UINT256_MUL},
        },
        SP1Prover, SP1Stdin,
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        SP1Prover::prove(UINT256_MUL, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_div() {
        utils::setup_logger();
        SP1Prover::prove(UINT256_DIV, SP1Stdin::new()).unwrap();
    }
}
