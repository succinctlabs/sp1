//! Generate + verify a core proof for bn254-c on a g1_add operation.

use rand::rngs::OsRng;
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use substrate_bn::{AffineG1, Fr, Group, G1};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BN254_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn encode_g1(p: G1) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some(a) = AffineG1::from_jacobian(p) {
        a.x().to_big_endian(&mut out[0..32]).unwrap();
        a.y().to_big_endian(&mut out[32..64]).unwrap();
    }
    out
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut rng = OsRng;
    let a = Fr::random(&mut rng);
    let b = Fr::random(&mut rng);
    let big_a = G1::one() * a;
    let big_b = G1::one() * b;
    let expected = encode_g1(G1::one() * (a + b));

    let mut input = Vec::with_capacity(1 + 128);
    input.push(0);
    input.extend_from_slice(&encode_g1(big_a));
    input.extend_from_slice(&encode_g1(big_b));

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), expected);
    info!("g1_add result matches host-side substrate-bn");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
