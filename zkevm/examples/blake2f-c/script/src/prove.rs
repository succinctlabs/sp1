//! Generate + verify a core proof for blake2f-c against the EIP-152
//! canonical test vector.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("BLAKE2F_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

const ROUNDS: u32 = 12;
const H_HEX: &str = "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
                    d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b";
const M_HEX: &str = "6162630000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000";
const T_HEX: &str = "03000000000000000000000000000000";
const F: u8 = 1;
const EXPECTED_HEX: &str = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                            7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let h = hex::decode(H_HEX.replace([' ', '\n'], "")).unwrap();
    let m = hex::decode(M_HEX.replace([' ', '\n'], "")).unwrap();
    let t = hex::decode(T_HEX).unwrap();
    let expected = hex::decode(EXPECTED_HEX.replace([' ', '\n'], "")).unwrap();

    let mut input = Vec::with_capacity(4 + 64 + 128 + 16 + 1);
    input.extend_from_slice(&ROUNDS.to_be_bytes());
    input.extend_from_slice(&h);
    input.extend_from_slice(&m);
    input.extend_from_slice(&t);
    input.push(F);

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    let out = proof.public_values.as_slice();
    assert_eq!(out, expected.as_slice());
    info!("output matches EIP-152 expected state");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
