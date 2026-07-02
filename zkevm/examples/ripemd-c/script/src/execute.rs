//! Execute ripemd-c and verify against host-computed RIPEMD-160.

use ripemd::{Digest, Ripemd160};
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("RIPEMD_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn ripemd160_host_padded(data: &[u8]) -> [u8; 32] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&digest);
    out
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    for input in &[
        &b""[..],
        &b"hello world"[..],
        &b"The quick brown fox jumps over the lazy dog"[..],
        &[0xab; 200][..],
    ] {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);

        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let guest_digest = public_values.as_slice();
        let host_digest = ripemd160_host_padded(input);

        info!(
            input_len = input.len(),
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "executed ripemd-c",
        );
        assert_eq!(guest_digest, host_digest);
    }
    info!("all digests match host-computed RIPEMD-160 (with 12-byte zero pad)");
}
