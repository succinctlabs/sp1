//! Execute the `hello-rust` guest under SP1's executor (no proof) and
//! verify the public output matches the input.

use sp1_sdk::{include_elf, utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF: Elf = include_elf!("hello-rust");

#[tokio::main]
async fn main() {
    utils::setup_logger();

    // The guest's `read_input` exposes the first chunk in the SP1 hint
    // stream. Push the entire private input as one chunk per the host-
    // side contract documented in `libzkevm/src/io.rs`.
    let input: &[u8] = b"hello from the host";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let client = ProverClient::builder().light().build().await;

    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    info!(
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        instructions = report.total_instruction_count(),
        syscalls = report.total_syscall_count(),
        "executed hello-rust",
    );

    let output = public_values.as_slice();
    info!(output = %core::str::from_utf8(output).unwrap_or("<non-utf8>"), "public output");
    assert_eq!(output, input, "guest's write_output must echo the read_input bytes");
    info!("output matches input");
}
