mod fp2_mul;
mod fp_add;
mod fp_mul;

pub use fp2_mul::*;
pub use fp_add::*;
pub use fp_mul::*;

#[cfg(test)]
mod tests {
    use crate::Program;
    use crate::{
        stark::CpuProver,
        utils::{
            self,
            tests::{BLS12381_FP2_MUL_ELF, BLS12381_FP_ADD_ELF, BLS12381_FP_MUL_ELF},
        },
    };

    #[test]
    fn test_bls12381_fp_add() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_ADD_ELF);
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp_mul() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_MUL_ELF);
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp2_mul() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_MUL_ELF);
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
