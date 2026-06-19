//! Execute invalid-hint-c with flag=0 (success) and flag=1 (invalid_hint).

use sp1_core_executor::StatusCode;
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("INVALID_HINT_C_ELF"));
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
            exit_code = report.exit_code,
            "flag=0: clean termination",
        );
        assert_eq!(report.exit_code, 0);
        assert_eq!(StatusCode::new(report.exit_code as u32), Some(StatusCode::SUCCESS));
    }

    {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&[1u8]);
        let (_pv, report) = client.execute(ELF, stdin).await.unwrap();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            exit_code = report.exit_code,
            "flag=1: zkvm_invalid_hint() halted with StatusCode::INVALID_HINT (exit code 3)",
        );
        assert_eq!(report.exit_code, 3);
        assert_eq!(
            StatusCode::new(report.exit_code as u32),
            Some(StatusCode::INVALID_HINT)
        );
    }
}
