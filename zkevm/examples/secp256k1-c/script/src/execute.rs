//! Execute secp256k1-c with a valid signature, then with a tampered one,
//! and check the guest accepts/rejects accordingly.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("SECP256K1_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn build_input(msg_hash: &[u8; 32], sig: &Signature, pubkey_xy: &[u8; 64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 64 + 64);
    buf.extend_from_slice(msg_hash);
    buf.extend_from_slice(&sig.to_bytes());
    buf.extend_from_slice(pubkey_xy);
    buf
}

fn pubkey_xy(sk: &SigningKey) -> [u8; 64] {
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    assert_eq!(bytes[0], 0x04);
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&bytes[1..]);
    xy
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    let sk = SigningKey::random(&mut OsRng);
    let xy = pubkey_xy(&sk);
    let msg = b"the quick brown fox jumps over the lazy dog";
    let msg_hash: [u8; 32] = Sha256::digest(msg).into();
    let signature: Signature = sk.sign_prehash(&msg_hash).unwrap();

    // Valid signature.
    {
        let input = build_input(&msg_hash, &signature, &xy);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            verified = out.first().copied().unwrap_or(0),
            "valid signature path",
        );
        assert_eq!(out, &[1u8], "guest rejected a valid signature");
    }

    // Tampered: flip a bit in the signature.
    {
        let mut tampered = signature.to_bytes();
        tampered[0] ^= 0x01;
        let mut input = Vec::with_capacity(32 + 64 + 64);
        input.extend_from_slice(&msg_hash);
        input.extend_from_slice(&tampered);
        input.extend_from_slice(&xy);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            verified = out.first().copied().unwrap_or(0),
            "tampered signature path",
        );
        assert_eq!(out, &[0u8], "guest accepted a tampered signature");
    }

    info!("secp256k1-c verified valid signature, rejected tampered signature");
}
