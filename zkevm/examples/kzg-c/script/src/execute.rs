//! Execute kzg-c against the bundled consensus-specs `verify_kzg_proof`
//! test vectors (correct + incorrect + invalid-encoding cases).

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;
use zkevm_fixtures::kzg;

const ELF_BYTES: &[u8] = include_bytes!(env!("KZG_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    let mut ran = 0usize;
    let mut skipped = 0usize;
    let mut invalid_seen = 0usize;
    for v in kzg::vectors() {
        if !v.has_canonical_lengths() {
            // Wrong-length inputs are rejected by the C ABI's fixed-width
            // `zkvm_bytes_48` / `zkvm_bytes_32` types before libzkevm
            // sees them, so the guest can never observe these cases.
            // Treat them as out-of-scope for this differential test.
            info!(case = v.name, "skipping non-canonical-length case");
            skipped += 1;
            continue;
        }

        let mut input = Vec::with_capacity(48 + 32 + 32 + 48);
        input.extend_from_slice(&v.commitment);
        input.extend_from_slice(&v.z);
        input.extend_from_slice(&v.y);
        input.extend_from_slice(&v.proof);

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);

        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        let expected: u8 = if v.expected_verified { 1 } else { 0 };

        info!(
            case = v.name,
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            invalid_input = v.is_invalid_input,
            verified = out.first().copied().unwrap_or(0),
            "kzg-c case",
        );
        assert_eq!(out, &[expected], "{}: guest disagreed with spec", v.name);
        ran += 1;
        if v.is_invalid_input {
            invalid_seen += 1;
        }
    }

    info!(
        ran = ran,
        skipped = skipped,
        invalid_inputs_run = invalid_seen,
        "kzg-c matched all spec outcomes (invalid-encoding is collapsed to `verified=false`)",
    );
}
