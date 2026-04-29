//! Generate + verify a core proof for kzg-c on a valid EIP-4844 opening.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("KZG_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

const COMMITMENT_HEX: &str =
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const Z_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const Y_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PROOF_HEX: &str =
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut input = Vec::with_capacity(48 + 32 + 32 + 48);
    input.extend_from_slice(&hex::decode(COMMITMENT_HEX).unwrap());
    input.extend_from_slice(&hex::decode(Z_HEX).unwrap());
    input.extend_from_slice(&hex::decode(Y_HEX).unwrap());
    input.extend_from_slice(&hex::decode(PROOF_HEX).unwrap());

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), &[1u8]);
    info!("guest reported KZG opening verified");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
