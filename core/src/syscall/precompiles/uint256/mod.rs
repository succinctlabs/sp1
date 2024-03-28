mod uint256_mul;

pub use uint256_mul::*;

#[cfg(test)]
mod tests {

    use crate::{
        utils::{
            self,
            ec::{field::FieldParameters, uint256::U256Field, utils::biguint_from_limbs},
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

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
