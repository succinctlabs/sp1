#![allow(dead_code)]
use std::error::Error;

use std::{fs::File, io::Read};

use tendermint_light_client_verifier::types::LightBlock;

pub fn load_light_block(block_height: u64) -> Result<LightBlock, Box<dyn Error>> {
    let mut file = File::open(format!("files/block_{}.json", block_height))?;
    let mut block_response_raw = String::new();
    file.read_to_string(&mut block_response_raw)
        .unwrap_or_else(|_| panic!("Failed to read block number {}", block_height));
    Ok(serde_json::from_str(&block_response_raw)?)
}
