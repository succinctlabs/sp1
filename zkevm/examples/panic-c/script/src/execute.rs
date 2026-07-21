//! Execute panic-c with both flag=0 (success) and flag=1 (abort()).

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("PANIC_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&[0u8]);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            output = %core::str::from_utf8(public_values.as_slice()).unwrap_or("<non-utf8>"),
            "flag=0: clean termination",
        );
    }

    {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&[1u8]);
        match client.execute(ELF, stdin).await {
            Ok((_pv, report)) => info!(
                cycles = report.total_instruction_count() + report.total_syscall_count(),
                "flag=1: executor returned Ok — guest halted with non-zero exit code",
            ),
            Err(e) => info!("flag=1: executor returned Err — {e}"),
        }
    }
}
