use sp1_sdk::{utils, ProverClient, SP1Stdin};

const PATCH_TEST_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// This script is used to test that SP1 patches are correctly applied and syscalls are triggered.
fn main() {
    utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (_, report) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");

    // Confirm there was at least 1 SHA_COMPUTE syscall.
    assert!(
        report.syscall_counts.contains_key(&sp1_core_executor::syscalls::SyscallCode::SHA_COMPRESS)
    );
    assert!(
        report.syscall_counts.contains_key(&sp1_core_executor::syscalls::SyscallCode::SHA_EXTEND)
    );

    // Confirm there was at least 1 of each ED25519 syscall.
    assert!(report.syscall_counts.contains_key(&sp1_core_executor::syscalls::SyscallCode::ED_ADD));
    assert!(
        report
            .syscall_counts
            .contains_key(&sp1_core_executor::syscalls::SyscallCode::ED_DECOMPRESS)
    );

    // Confirm there was at least 1 KECCAK_PERMUTE syscall.
    assert!(
        report
            .syscall_counts
            .contains_key(&sp1_core_executor::syscalls::SyscallCode::KECCAK_PERMUTE)
    );

    // Confirm there was at least 1 SECP256K1_ADD, SECP256K1_DOUBLE and SECP256K1_DECOMPRESS syscall.
    assert!(
        report
            .syscall_counts
            .contains_key(&sp1_core_executor::syscalls::SyscallCode::SECP256K1_ADD)
    );
    assert!(
        report
            .syscall_counts
            .contains_key(&sp1_core_executor::syscalls::SyscallCode::SECP256K1_DOUBLE)
    );
    assert!(
        report
            .syscall_counts
            .contains_key(&sp1_core_executor::syscalls::SyscallCode::SECP256K1_DECOMPRESS)
    );

    println!("Total instructions: {:?}", report.total_instruction_count());
    println!("Successfully executed the program & confirmed syscalls.");
}
