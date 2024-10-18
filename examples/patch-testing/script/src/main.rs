use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

const PATCH_TEST_ELF: &[u8] = include_elf!("patch-testing-program");

/// This script is used to test that SP1 patches are correctly applied and syscalls are triggered.
pub fn main() {
    utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (_, report) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");

    // Confirm there was at least 1 SHA_COMPUTE syscall.
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SHA_COMPRESS], 0);
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SHA_EXTEND], 0);

    // Confirm there was at least 1 of each ED25519 syscall.
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::ED_ADD], 0);
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::ED_DECOMPRESS], 0);

    // Confirm there was at least 1 KECCAK_PERMUTE syscall.
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::KECCAK_PERMUTE], 0);

    // Confirm there was at least 1 SECP256K1_ADD, SECP256K1_DOUBLE and SECP256K1_DECOMPRESS syscall.
    assert_ne!(report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_ADD], 0);
    assert_ne!(
        report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_DOUBLE],
        0
    );
    assert_ne!(
        report.syscall_counts[sp1_core_executor::syscalls::SyscallCode::SECP256K1_DECOMPRESS],
        0
    );

    println!("Total instructions: {:?}", report.total_instruction_count());
    println!("Successfully executed the program & confirmed syscalls.");
}
