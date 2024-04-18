mod air;

pub use air::*;

#[cfg(test)]
mod tests {

    use crate::{
        runtime::Program,
        utils::{
            self,
            ec::{field::FieldParameters, uint256::U256Field, utils::biguint_from_limbs},
            run_test_io,
            tests::{UINT256_DIV, UINT256_MUL},
        },
        SP1Stdin,
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(UINT256_MUL);
        run_test_io(program, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_div() {
        utils::setup_logger();
        let program = Program::from(UINT256_DIV);
        run_test_io(program, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
