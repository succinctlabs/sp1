#![allow(dead_code)]
use std::collections::HashMap;
use std::error::Error;

use reqwest::Client;
use tendermint::{block::signed_header::SignedHeader, node::Id, validator::Set};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

use crate::{BlockValidatorSet, CommitResponse, ValidatorSetResponse};

pub fn sort_signatures_by_validators_power_desc(
    signed_header: &mut SignedHeader,
    validators_set: &ValidatorSet,
) {
    let validator_powers: HashMap<_, _> = validators_set
        .validators()
        .iter()
        .map(|v| (v.address, v.power()))
        .collect();

    signed_header.commit.signatures.sort_by(|a, b| {
        let power_a = a
            .validator_address()
            .and_then(|addr| validator_powers.get(&addr))
            .unwrap_or(&0);
        let power_b = b
            .validator_address()
            .and_then(|addr| validator_powers.get(&addr))
            .unwrap_or(&0);
        power_b.cmp(power_a)
    });
}

pub async fn fetch_json<T>(
    client: &Client,
    url: &str,
    block_height: u64,
) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let response = client
        .get(url)
        .query(&[("height", block_height.to_string().as_str())])
        .send()
        .await?
        .json::<T>()
        .await?;
    Ok(response)
}

pub async fn generate_light_block_at_given_block_height(
    block_height: u64,
    peer_id: [u8; 20],
) -> Result<LightBlock, Box<dyn Error>> {
    let client = Client::new();
    const BASE_URL: &str = "https://celestia-mocha-rpc.publicnode.com:443";

    let commit_response =
        fetch_json::<CommitResponse>(&client, &format!("{}/commit", BASE_URL), block_height)
            .await?;
    let mut signed_header = commit_response.result.signed_header;

    let validator_response = fetch_json::<ValidatorSetResponse>(
        &client,
        &format!("{}/validators", BASE_URL),
        block_height,
    )
    .await?;
    let block_validator_set: BlockValidatorSet = validator_response.result;
    let validators = Set::new(block_validator_set.validators, None);

    let next_validator_response = fetch_json::<ValidatorSetResponse>(
        &client,
        &format!("{}/validators", BASE_URL),
        block_height + 1,
    )
    .await?;
    let next_block_validator_set = next_validator_response.result;
    let next_validators = Set::new(next_block_validator_set.validators, None);

    sort_signatures_by_validators_power_desc(&mut signed_header, &validators);
    Ok(LightBlock::new(
        signed_header,
        validators,
        next_validators,
        Id::new(peer_id),
    ))
}
