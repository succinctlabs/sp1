//! Generate + verify a core proof for modexp-c on a representative
//! 256-bit modular exponentiation.

use num_bigint::BigUint;
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("MODEXP_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let base = vec![3u8];
    let exp = 65537u32.to_be_bytes().to_vec();
    let modulus = hex::decode(
        "fffffffffffffffffffffffffffffffefffffffffffffffe\
         ffffffffffffffffffffffffffffffff",
    )
    .unwrap();

    let mut input = Vec::with_capacity(12 + base.len() + exp.len() + modulus.len());
    input.extend_from_slice(&(base.len() as u32).to_be_bytes());
    input.extend_from_slice(&(exp.len() as u32).to_be_bytes());
    input.extend_from_slice(&(modulus.len() as u32).to_be_bytes());
    input.extend_from_slice(&base);
    input.extend_from_slice(&exp);
    input.extend_from_slice(&modulus);

    let m = BigUint::from_bytes_be(&modulus);
    let b = BigUint::from_bytes_be(&base);
    let e = BigUint::from_bytes_be(&exp);
    let r = b.modpow(&e, &m).to_bytes_be();
    let mut expected = vec![0u8; modulus.len()];
    let off = modulus.len() - r.len();
    expected[off..].copy_from_slice(&r);

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), expected.as_slice());
    info!("modexp output matches host-computed value");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
