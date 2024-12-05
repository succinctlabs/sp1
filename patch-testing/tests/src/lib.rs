//#[derive(serde::Serialize, serde::Deserialize)]
//pub enum TestName {
//    Keccak,
//    Sha256,
//    Curve25519DalekNg,
//    Curve25519Dalek,
//    Ed25519Dalek,
//    Ed25519Consensus,
//    K256,
//    P256,
//    Secp256k1,
//}


#[cfg(test)]
mod tests {
    use sp1_sdk::{include_elf, utils, ExecutionReport, ProverClient, SP1Stdin};

    const PATCH_TEST_ELF: &[u8] = include_elf!("patch-testing-program");

    use patch_testing_program::TestName;

    fn run(test_name: TestName) -> ExecutionReport {
        utils::setup_logger();
        let mut stdin = SP1Stdin::new();
        stdin.write(&test_name);

        let client = ProverClient::new();
        let (_, report) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");

        report
    }

    #[test]
    fn test_keccak() {
        run(TestName::Keccak);
    }

    #[test]
    fn test_sha256() {
        run(TestName::Sha256);
    }

    #[test]
    fn test_curve25519_dalek_ng() {
        run(TestName::Curve25519DalekNg);
    }

    #[test]
    fn test_curve25519_dalek() {
        run(TestName::Curve25519Dalek);
    }

    #[test]
    fn test_ed25519_dalek() {
        run(TestName::Ed25519Dalek);
    }

    #[test]
    fn test_ed25519_consensus() {
        run(TestName::Ed25519Consensus);
    }

    #[test]
    fn test_k256_patch() {
        run(TestName::K256);
    }

    #[test]
    fn test_p256_patch() {
        run(TestName::P256);
    }

    #[test]
    fn test_secp256k1_patch() {
        run(TestName::Secp256k1);
    }
}

///// This script is used to test that SP1 patches are correctly applied and syscalls are triggered.
//pub fn main() {
//    utils::setup_logger();
//
//    let stdin = SP1Stdin::new();
//
//    let client = ProverClient::new();
//    let (_, report) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
//    //
//    //// Confirm there was at least 1 SHA_COMPUTE syscall.
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SHA_COMPRESS], 0);
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SHA_EXTEND], 0);
//    //
//    //// Confirm there was at least 1 of each ED25519 syscall.
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::ED_ADD], 0);
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::ED_DECOMPRESS], 0);
//    //
//    //// Confirm there was at least 1 KECCAK_PERMUTE syscall.
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::KECCAK_PERMUTE], 0);
//    //
//    //// Confirm there was at least 1 SECP256K1_ADD, SECP256K1_DOUBLE and SECP256K1_DECOMPRESS syscall.
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_ADD], 0);
//    //assert_ne!(
//    //    report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_DOUBLE],
//    //    0
//    //);
//    //assert_ne!(
//    //    report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_DECOMPRESS],
//    //    0
//    //);
//    //
//    //// Confirm there was at least 1 SECP256R1_ADD and SECP256R1_DOUBLE syscall.
//    //assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256R1_ADD], 0);
//    //assert_ne!(
//    //    report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256R1_DOUBLE],
//    //    0
//    //);
//
//    println!("Total instructions: {:?}", report.total_instruction_count());
//    println!("Successfully executed the program & confirmed syscalls.");
//}
