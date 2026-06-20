//! Generate + verify a core proof for bls12-c on a g1_add operation.

use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BLS12_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut rng = OsRng;
    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);
    let big_a = G1Affine::from(G1Projective::generator() * a);
    let big_b = G1Affine::from(G1Projective::generator() * b);
    let expected = G1Affine::from(G1Projective::generator() * (a + b)).to_uncompressed();

    let mut input = Vec::with_capacity(1 + 192);
    input.push(0);
    input.extend_from_slice(&big_a.to_uncompressed());
    input.extend_from_slice(&big_b.to_uncompressed());

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), expected);
    info!("g1_add result matches host-side bls12_381");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
