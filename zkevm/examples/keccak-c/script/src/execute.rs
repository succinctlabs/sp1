//! Execute keccak-c and verify against host-computed keccak256.

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("KECCAK_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn keccak256_host(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    for input in &[
        &b""[..],
        &b"hello world"[..],
        &[0u8; 136][..],
        &[0xab; 200][..],
        &b"The quick brown fox jumps over the lazy dog"[..],
    ] {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);

        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let guest_digest = public_values.as_slice();
        let host_digest = keccak256_host(input);

        info!(
            input_len = input.len(),
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            keccak_permute_calls = report
                .syscall_counts
                .iter()
                .filter(|(name, _)| format!("{name:?}").contains("KECCAK"))
                .map(|(_, n)| *n)
                .sum::<u64>(),
            "executed keccak-c",
        );
        assert_eq!(guest_digest, host_digest);
    }
    info!("all digests match host-computed keccak256");
}
