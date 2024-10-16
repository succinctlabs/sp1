use sp1_sdk::{include_elf, SP1ProofWithPublicValues};
use std::time::Duration;

use sp1_sdk::{utils, ProverClient, SP1Stdin};

use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

use crate::util::load_light_block;

const TENDERMINT_ELF: &[u8] = include_elf!("tendermint-program");

mod util;

fn get_light_blocks() -> (LightBlock, LightBlock) {
    let light_block_1 = load_light_block(2279100).expect("Failed to generate light block 1");
    let light_block_2 = load_light_block(2279130).expect("Failed to generate light block 2");
    (light_block_1, light_block_2)
}

pub fn main() {
    // Generate proof.
    utils::setup_logger();

    // Load light blocks from the `files` subdirectory
    let (light_block_1, light_block_2) = get_light_blocks();

    let expected_verdict = verify_blocks(light_block_1.clone(), light_block_2.clone());

    let mut stdin = SP1Stdin::new();

    let encoded_1 = serde_cbor::to_vec(&light_block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&light_block_2).unwrap();

    stdin.write_vec(encoded_1);
    stdin.write_vec(encoded_2);

    // TODO: normally we could just write the LightBlock, but bincode doesn't work with LightBlock.
    // The following code will panic.
    // let encoded: Vec<u8> = bincode::serialize(&light_block_1).unwrap();
    // let decoded: LightBlock = bincode::deserialize(&encoded[..]).unwrap();

    let client = ProverClient::new();
    let (pk, vk) = client.setup(TENDERMINT_ELF);

    client.execute(TENDERMINT_ELF, stdin.clone()).run().expect("proving failed");

    let proof = client.prove(&pk, stdin).run().expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Verify the public values
    let mut expected_public_values: Vec<u8> = Vec::new();
    expected_public_values.extend(light_block_1.signed_header.header.hash().as_bytes());
    expected_public_values.extend(light_block_2.signed_header.header.hash().as_bytes());
    expected_public_values.extend(serde_cbor::to_vec(&expected_verdict).unwrap());

    assert_eq!(proof.public_values.as_ref(), expected_public_values);

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

fn verify_blocks(light_block_1: LightBlock, light_block_2: LightBlock) -> Verdict {
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let verify_time = light_block_2.time() + Duration::from_secs(20);
    vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}
