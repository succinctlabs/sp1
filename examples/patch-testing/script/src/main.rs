use ed25519_consensus::{SigningKey, VerificationKey};
use rand::thread_rng;
use sp1_sdk::{utils, ProverClient, SP1Stdin};

const PATCH_TEST_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
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
        .expect("proving failed");

    // Confirm that there was at least 1 SHA_COMPUTE syscall.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::SHA_COMPRESS));
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::SHA_EXTEND));

    // Confirm there were ED25519_COMPUTE syscalls.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::ED_ADD));
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::ED_DECOMPRESS));

    // Confirm that there was at least 1 KECCAK_PERMUTE syscall.
    assert!(report
        .syscall_counts
        .contains_key(&sp1_core::runtime::SyscallCode::KECCAK_PERMUTE));

    println!("Report: {:?}", report);
    println!("Total cycle count: {}", report.total_instruction_count());
    println!("successfully executed the program!")
}
