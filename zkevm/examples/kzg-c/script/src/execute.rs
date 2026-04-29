//! Execute kzg-c against an EIP-4844 KZG opening test vector.

use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("KZG_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

/// Test vector taken from the consensus-spec KZG fixtures
/// (`verify_kzg_proof_case_correct_proof_02e696ada7d4631d`):
///   commitment = identity-G1 (compressed)
///   z = 2, y = 0
///   proof = identity-G1
/// The KZG check passes — opening (0) at z=2 of the zero polynomial
/// committed to the identity is trivially correct.
const COMMITMENT_HEX: &str =
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const Z_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const Y_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PROOF_HEX: &str =
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn build_input(commitment: &[u8], z: &[u8], y: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48 + 32 + 32 + 48);
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(z);
    buf.extend_from_slice(y);
    buf.extend_from_slice(proof);
    buf
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    let commitment = hex::decode(COMMITMENT_HEX).unwrap();
    let z = hex::decode(Z_HEX).unwrap();
    let y = hex::decode(Y_HEX).unwrap();
    let proof = hex::decode(PROOF_HEX).unwrap();

    // Valid opening.
    {
        let input = build_input(&commitment, &z, &y, &proof);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            verified = out.first().copied().unwrap_or(0),
            "valid KZG opening",
        );
        assert_eq!(out, &[1u8], "guest rejected a valid KZG opening");
    }

    // Tampered: claim y = 1 instead of 0; the same proof must not verify.
    {
        let mut tampered_y = y.clone();
        tampered_y[31] = 1;
        let input = build_input(&commitment, &z, &tampered_y, &proof);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            verified = out.first().copied().unwrap_or(0),
            "tampered KZG opening",
        );
        assert_eq!(out, &[0u8], "guest accepted a tampered KZG opening");
    }

    info!("kzg-c verified valid opening, rejected tampered opening");
}
