#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
use std::sync::Arc;

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<EthClientExecutorInput>(&input).unwrap();

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let header = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();

    // Commit the block hash.
    sp1_zkvm::io::commit(&block_hash);
}
