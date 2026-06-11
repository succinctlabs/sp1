//! Execute the `hello-c` C guest under SP1's executor (no proof) and
//! verify the public output matches the input.

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("HELLO_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let input: &[u8] = b"hello from the host (C)";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let client = ProverClient::builder().light().build().await;

    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    info!(
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        instructions = report.total_instruction_count(),
        syscalls = report.total_syscall_count(),
        "executed hello-c",
    );

    let output = public_values.as_slice();
    info!(output = %core::str::from_utf8(output).unwrap_or("<non-utf8>"), "public output");
    assert_eq!(output, input, "guest's write_output must echo the read_input bytes");
    info!("output matches input");
}
