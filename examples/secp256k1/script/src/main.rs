use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use rand::thread_rng;
use elliptic_curve::sec1::ToEncodedPoint;

const ELF: Elf = include_elf!("secp256k1-program");

#[tokio::main]
async fn main() {
    // Generate proof.
    sp1_sdk::utils::setup_logger();

    let mut rng = thread_rng();
    let secret_key = k256::SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let _decompressed = encoded.as_bytes();
    let compressed = public_key.to_sec1_bytes();

    let stdin = SP1Stdin::from(&compressed);
    
    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.expect("setup failed");
    let proof = client.prove(&pk, stdin).core().await.expect("proving failed");

    // Verify proof.
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    println!("successfully generated and verified proof for the program!")
}

