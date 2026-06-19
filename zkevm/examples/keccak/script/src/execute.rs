//! Execute the keccak guest and check the digest matches host-computed keccak256.

use sp1_sdk::{include_elf, utils, Elf, Prover, ProverClient, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};
use tracing::info;

const ELF: Elf = include_elf!("keccak");

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

    // Try a few shapes: empty, short (< rate), exactly rate, > rate.
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
            "executed keccak",
        );

        assert_eq!(guest_digest, host_digest, "digest mismatch for input len {}", input.len());
    }

    info!("all digests match host-computed keccak256");
}
