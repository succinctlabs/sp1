//! Execute sha256-c and verify against host-computed SHA-256.

use sha2::Digest;
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("SHA256_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn sha256_host(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    // SHA-256's block size is 64 bytes. Same coverage as the Rust `sha256` example.
    for input in &[
        &b""[..],
        &b"hello world"[..],
        &[0u8; 64][..],
        &[0xab; 200][..],
        &b"The quick brown fox jumps over the lazy dog"[..],
    ] {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);

        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let guest_digest = public_values.as_slice();
        let host_digest = sha256_host(input);

        info!(
            input_len = input.len(),
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            sha_compress_calls = report
                .syscall_counts
                .iter()
                .filter(|(name, _)| format!("{name:?}").contains("SHA_COMPRESS"))
                .map(|(_, n)| *n)
                .sum::<u64>(),
            "executed sha256-c",
        );

        assert_eq!(guest_digest, host_digest, "digest mismatch for input len {}", input.len());
    }

    info!("all digests match host-computed sha256");
}
