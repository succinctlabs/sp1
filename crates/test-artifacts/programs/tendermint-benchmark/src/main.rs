#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use serde::Deserialize;
use tendermint::{node::Id, validator::Info};
use tendermint_light_client_verifier::{
    options::Options,
    types::{LightBlock, SignedHeader, ValidatorSet},
    ProdVerifier, Verdict, Verifier,
};

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

pub fn main() {
    let peer_id: [u8; 20] = [
        0x72, 0x6b, 0xc8, 0xd2, 0x60, 0x38, 0x7c, 0xf5, 0x6e, 0xcf, 0xad, 0x3a, 0x6b, 0xf6, 0xfe,
        0xcd, 0x90, 0x3e, 0x18, 0xa2,
    ];

    println!("cycle-tracker-start: io");
    // Generate the Light Block's without testgen
    let file_content = include_bytes!("./fixtures/1/signed_header.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");

    let commit_response: CommitResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let signed_header = commit_response.result.signed_header;

    let file_content = include_bytes!("./fixtures/1/validators.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");
    let validators_response: ValidatorSetResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let validators = validators_response.result;
    let validators = ValidatorSet::new(validators.validators, None);

    let file_content = include_bytes!("./fixtures/1/next_validators.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");
    let next_validators_response: ValidatorSetResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let next_validators = next_validators_response.result;
    let next_validators = ValidatorSet::new(next_validators.validators, None);

    // Create a default light block with a valid chain-id for height `1` with a timestamp 20
    // secs before now (to be treated as trusted state)
    let light_block_1: LightBlock =
        LightBlock::new(signed_header, validators, next_validators, Id::new(peer_id));

    // // Generate the Light Block's without testgen
    let file_content = include_bytes!("./fixtures/2/signed_header.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");

    let commit_response: CommitResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let signed_header = commit_response.result.signed_header;

    let file_content = include_bytes!("./fixtures/2/validators.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");
    let validators_response: ValidatorSetResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let validators = validators_response.result;
    let validators = ValidatorSet::new(validators.validators, None);

    let file_content = include_bytes!("./fixtures/2/next_validators.json");
    let file_content_str =
        core::str::from_utf8(file_content).expect("Failed to convert file content to string");
    let next_validators_response: ValidatorSetResponse =
        serde_json::from_str(file_content_str).expect("Failed to parse JSON");
    let next_validators = next_validators_response.result;
    let next_validators = ValidatorSet::new(next_validators.validators, None);
    // Create a default light block with a valid chain-id for height `1` with a timestamp 20
    // secs before now (to be treated as trusted state)
    let light_block_2: LightBlock =
        LightBlock::new(signed_header, validators, next_validators, Id::new(peer_id));
    println!("cycle-tracker-end: io");

    println!("cycle-tracker-start: verify");
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
    println!("cycle-tracker-end: verify");

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {:?}", v),
    }
}
