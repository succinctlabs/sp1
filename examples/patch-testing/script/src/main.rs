use ed25519_consensus::{SigningKey, VerificationKey};
use rand::thread_rng;
use sp1_sdk::{utils, ProverClient, SP1Stdin};

const PATCH_TEST_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// This script is used to test that SP1 patches are correctly applied and syscalls are triggered.
fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    let sk = SigningKey::new(thread_rng());
    let vk = VerificationKey::from(&sk);

    let msg = b"ed25519-consensus test message";

    let sig = sk.sign(msg);
    stdin.write(&sig);
    stdin.write(&vk);
    stdin.write_vec(msg.to_vec());

    let client = ProverClient::new();
    let (_, report) = client
        .execute(PATCH_TEST_ELF, stdin)
        .run()
        .expect("executing failed");

    // Confirm there was at least 1 SHA_COMPUTE syscall.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::SHA_COMPRESS));
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::SHA_EXTEND));

    // Confirm there was at least 1 ED25519_COMPUTE syscalls.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::ED_ADD));
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::ED_DECOMPRESS));

    // Confirm there was at least 1 KECCAK_PERMUTE syscall.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::KECCAK_PERMUTE));

    println!("Successfully executed the program & confirmed syscalls.");
}
