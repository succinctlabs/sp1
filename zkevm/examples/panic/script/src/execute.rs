//! Execute the panic guest twice: once with the success flag, once with
//! the panic flag, and report what SP1 reports back in each case.

use sp1_sdk::{include_elf, utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF: Elf = include_elf!("panic");

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    // -------- success path: flag = 0 --------
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

    // -------- panic path: flag = 1 --------
    //
    // The guest panics, which routes through Rust's panic handler and
    // ultimately `syscall_halt(1)`. Depending on SDK version this may
    // surface as either an `Err(...)` from `execute` (if the executor
    // treats non-zero exit as an error by default) or as a successful
    // `Ok(...)` with the exit code embedded in the report. Handle both.
    {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&[1u8]);
        match client.execute(ELF, stdin).await {
            Ok((_pv, report)) => {
                info!(
                    cycles = report.total_instruction_count() + report.total_syscall_count(),
                    "flag=1: executor returned Ok — guest halted with non-zero exit code",
                );
            }
            Err(e) => {
                info!("flag=1: executor returned Err as expected — {e}");
            }
        }
    }
}
