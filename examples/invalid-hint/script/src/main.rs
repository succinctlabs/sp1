//! Demonstrates SP1's exit code 3 (`StatusCode::INVALID_HINT`) for
//! prover-hint failures.
//!
//! Runs the same guest program twice through the executor:
//!   1. trigger=0 → program runs normally and exits 0.
//!   2. trigger=1 → program calls `sp1_lib::invalid_hint!`, writes a
//!      diagnostic to stderr, and halts with exit code 3.
//!
//! This is the primitive the patched crypto crates use when a hint
//! fails verification — exit 3 distinguishes a malicious prover's
//! "wrong hint" from a regular Rust panic (exit 1).

use sp1_core_executor::StatusCode;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("invalid-hint-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let client = ProverClient::from_env().await;

    // Case 1: happy path. trigger=0 → program commits & exits 0.
    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8);
    let (pv, report) = client.execute(ELF, stdin).await.expect("execute failed");
    println!("[trigger=0] exit_code = {}", report.exit_code);
    assert_eq!(report.exit_code, 0);
    assert_eq!(StatusCode::new(report.exit_code as u32), Some(StatusCode::SUCCESS));
    let _ = pv;

    // Case 2: invalid-hint path. trigger=1 → invalid_hint! → exit 3.
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);
    let (_pv, report) = client.execute(ELF, stdin).await.expect("execute failed");
    println!("[trigger=1] exit_code = {}", report.exit_code);
    assert_eq!(report.exit_code, 3);
    assert_eq!(
        StatusCode::new(report.exit_code as u32),
        Some(StatusCode::INVALID_HINT)
    );

    println!(
        "OK: invalid_hint! halts with exit code 3 (StatusCode::INVALID_HINT), \
         distinct from a regular panic (exit code 1)."
    );
}
