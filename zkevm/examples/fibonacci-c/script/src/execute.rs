//! Execute fibonacci-c under SP1's executor.

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("FIBONACCI_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);
const N: u32 = 1000;

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&N.to_le_bytes());

    let client = ProverClient::builder().light().build().await;
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();

    let bytes = public_values.as_slice();
    assert_eq!(bytes.len(), 4);
    let result = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    info!(
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        n = N,
        fib_mod_7919 = result,
        "executed fibonacci-c",
    );
    assert_eq!(result, 5965, "fib(1000) % 7919 expected 5965");
}
