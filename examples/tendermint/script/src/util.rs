#![allow(dead_code)]
use std::collections::HashMap;
use std::error::Error;

use reqwest::Client;
use serde::Deserialize;
use tendermint::{
    block::signed_header::SignedHeader,
    node::Id,
    validator::{Info, Set},
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

pub async fn fetch_latest_commit(
    client: &Client,
    url: &str,
) -> Result<CommitResponse, Box<dyn Error>> {
    let response: CommitResponse = client
        .get(url)
        .send()
        .await?
        .json::<CommitResponse>()
        .await?;
    Ok(response)
}

pub async fn fetch_commit(
    client: &Client,
    url: &str,
    block_height: u64,
) -> Result<CommitResponse, Box<dyn Error>> {
    let response: CommitResponse = client
        .get(url)
        .query(&[
            ("height", block_height.to_string().as_str()),
            ("per_page", "100"), // helpful only when fetching validators
        ])
        .send()
        .await?
        .json::<CommitResponse>()
        .await?;
    Ok(response)
}

pub async fn fetch_validators(
    client: &Client,
    url: &str,
    block_height: u64,
) -> Result<Vec<Info>, Box<dyn Error>> {
    let mut validators = vec![];
    let mut collected_validators = 0;
    let mut page_index = 1;
    loop {
        let response = client
            .get(url)
            .query(&[
                ("height", block_height.to_string().as_str()),
                ("per_page", "100"),
                ("page", page_index.to_string().as_str()),
            ])
            .send()
            .await?
            .json::<ValidatorSetResponse>()
            .await?;
        let block_validator_set: BlockValidatorSet = response.result;
        validators.extend(block_validator_set.validators);
        collected_validators += block_validator_set.count.parse::<i32>().unwrap();

        if collected_validators >= block_validator_set.total.parse::<i32>().unwrap() {
            break;
        }
        page_index += 1;
    }

    Ok(validators)
}

pub async fn fetch_light_block(
    block_height: u64,
    peer_id: [u8; 20],
    base_url: &str,
) -> Result<LightBlock, Box<dyn Error>> {
    let client = Client::new();

    let commit_response =
        fetch_commit(&client, &format!("{}/commit", base_url), block_height).await?;
    let mut signed_header = commit_response.result.signed_header;

    let validator_response =
        fetch_validators(&client, &format!("{}/validators", base_url), block_height).await?;

    let validators = Set::new(validator_response, None);

    let next_validator_response = fetch_validators(
        &client,
        &format!("{}/validators", base_url),
        block_height + 1,
    )
    .await?;
    let next_validators = Set::new(next_validator_response, None);

    sort_signatures_by_validators_power_desc(&mut signed_header, &validators);
    Ok(LightBlock::new(
        signed_header,
        validators,
        next_validators,
        Id::new(peer_id),
    ))
}
