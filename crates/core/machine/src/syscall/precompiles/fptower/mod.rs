mod fp;
mod fp2_addsub;
mod fp2_mul;

pub use fp::*;
pub use fp2_addsub::*;
pub use fp2_mul::*;

#[cfg(test)]
mod tests {
    use sp1_stark::CpuProver;

    use sp1_core_executor::{
        programs::tests::{
            BLS12381_FP2_ADDSUB_ELF, BLS12381_FP2_MUL_ELF, BLS12381_FP_ELF, BN254_FP2_ADDSUB_ELF,
            BN254_FP2_MUL_ELF, BN254_FP_ELF,
        },
        Program,
    };

    use crate::utils;

    #[test]
    fn test_bls12381_fp_ops() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp2_addsub() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_ADDSUB_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp2_mul() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_MUL_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_fp_ops() {
        utils::setup_logger();
        let program = Program::from(BN254_FP_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_fp2_addsub() {
        utils::setup_logger();
        let program = Program::from(BN254_FP2_ADDSUB_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_fp2_mul() {
        utils::setup_logger();
        let program = Program::from(BN254_FP2_MUL_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
