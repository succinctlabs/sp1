#![allow(dead_code)]
use std::{collections::HashMap, error::Error};

use std::{
    fs::File,
    io::{Read, Write},
};

use serde::{Deserialize, Serialize};

use tendermint::{
    block::signed_header::SignedHeader,
    validator::Info,
};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

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

fn write_to_file<S: Serialize>(input: &S, filename: &str) -> Result<(), Box<dyn Error>> {
    let json_string = serde_json::to_string(input)?;
    let mut file = File::create(filename)?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
}

pub fn sort_signatures_by_validators_power_desc(
    signed_header: &mut SignedHeader,
    validators_set: &ValidatorSet,
) {
    let validator_powers: HashMap<_, _> =
        validators_set.validators().iter().map(|v| (v.address, v.power())).collect();

    signed_header.commit.signatures.sort_by(|a, b| {
        let power_a =
            a.validator_address().and_then(|addr| validator_powers.get(&addr)).unwrap_or(&0);
        let power_b =
            b.validator_address().and_then(|addr| validator_powers.get(&addr)).unwrap_or(&0);
        power_b.cmp(power_a)
    });
}

pub fn load_light_block(block_height: u64) -> Result<LightBlock, Box<dyn Error>> {
    let mut file = File::open(&format!("files/block_{}.json", block_height))?;
    let mut block_response_raw = String::new();
    file.read_to_string(&mut block_response_raw)
        .expect(&format!("Failed to read block number {}", block_height));
    Ok(serde_json::from_str(&block_response_raw)?)
}
