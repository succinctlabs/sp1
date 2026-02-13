use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

use tendermint_script::util::load_light_block;

const TENDERMINT_ELF: Elf = include_elf!("tendermint-program");

fn get_light_blocks() -> (LightBlock, LightBlock) {
    let light_block_1 = load_light_block(2279100).expect("Failed to generate light block 1");
    let light_block_2 = load_light_block(2279130).expect("Failed to generate light block 2");
    (light_block_1, light_block_2)
}

#[tokio::main]
async fn main() {
    // Generate proof.
    // utils::setup_tracer();
    sp1_sdk::utils::setup_logger();

    // Load light blocks from the `files` subdirectory
    let (light_block_1, light_block_2) = get_light_blocks();
    let expected_verdict = verify_blocks(light_block_1.clone(), light_block_2.clone());

    let mut stdin = SP1Stdin::default();

    let encoded_1 = serde_cbor::to_vec(&light_block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&light_block_2).unwrap();

    stdin.write_vec(encoded_1);
    stdin.write_vec(encoded_2);

    let client = ProverClient::from_env().await;
    let pk = client.setup(TENDERMINT_ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    client.verify(&proof, &pk.verifying_key(), None).unwrap();

    // Verify the public values
    let mut expected_public_values: Vec<u8> = Vec::new();
    expected_public_values.extend(light_block_1.signed_header.header.hash().as_bytes());
    expected_public_values.extend(light_block_2.signed_header.header.hash().as_bytes());
    expected_public_values.extend(serde_cbor::to_vec(&expected_verdict).unwrap());

    assert_eq!(proof.public_values.as_ref(), expected_public_values);
}

fn verify_blocks(light_block_1: LightBlock, light_block_2: LightBlock) -> Verdict {
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: std::time::Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let verify_time = light_block_2.time() + std::time::Duration::from_secs(20);
    vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}
