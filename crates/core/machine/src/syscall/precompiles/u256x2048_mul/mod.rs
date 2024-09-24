mod air;

pub use air::*;

#[cfg(test)]
mod tests {
    use sp1_core_executor::{programs::tests::U256XU2048_MUL_ELF, Program};
    use sp1_curves::{params::FieldParameters, uint256::U256Field, utils::biguint_from_limbs};
    use sp1_stark::CpuProver;

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test_io},
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(U256XU2048_MUL_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }
}
