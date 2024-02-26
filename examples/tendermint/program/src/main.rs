#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use serde::Deserialize;
use tendermint::validator::Info;
use tendermint_light_client_verifier::{
    options::Options, types::SignedHeader, ProdVerifier, Verdict, Verifier,
};
use utils::generate_light_block_at_given_block_height;
mod utils;

#[derive(Debug, Deserialize)]
pub struct CommitResponse {
    pub result: SignedHeaderWrapper,
}

#[derive(Debug, Deserialize)]
pub struct SignedHeaderWrapper {
    pub signed_header: SignedHeader,
}

#[derive(Debug, Deserialize)]
pub struct ValidatorSetResponse {
    pub result: BlockValidatorSet,
}

#[derive(Debug, Deserialize)]
pub struct BlockValidatorSet {
    pub block_height: String,
    pub validators: Vec<Info>,
    pub count: String,
    pub total: String,
}

#[tokio::main]
async fn main() {
    let peer_id: [u8; 20] = [
        0x72, 0x6b, 0xc8, 0xd2, 0x60, 0x38, 0x7c, 0xf5, 0x6e, 0xcf, 0xad, 0x3a, 0x6b, 0xf6, 0xfe,
        0xcd, 0x90, 0x3e, 0x18, 0xa2,
    ];

    let light_block_1 = generate_light_block_at_given_block_height(10000, peer_id)
        .await
        .expect("Failed to generate light block 1");

    // Create a default light block with a valid chain-id for height `1` with a timestamp 20
    // secs before now (to be treated as trusted state)
    let light_block_2 = generate_light_block_at_given_block_height(10020, peer_id)
        .await
        .expect("Failed to generate light block 2");

    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };

    let verify_time = light_block_2.time() + Duration::from_secs(20);

    let verdict = vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {:?}", v),
    }
}
