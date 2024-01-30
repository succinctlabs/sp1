#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use succinct_zkvm::io;
use zeth_lib::{
    builder::{BlockBuilderStrategy, EthereumStrategy},
    consts::ETH_MAINNET_CHAIN_SPEC,
    input::Input,
    EthereumTxEssence,
};

fn main() {
    // Read the input previous block and transaction data
    println!("cycle-tracker-start: read input");
    let input = io::read::<Input<EthereumTxEssence>>();
    println!("cycle-tracker-end: read input");
    // Build the resulting block
    let (header, state) = EthereumStrategy::build_from(&ETH_MAINNET_CHAIN_SPEC, input)
        .expect("Failed to build the resulting block");
    // Output the resulting block's hash to the journal
    let hash = header.hash();
    println!("Resulting block hash: {:x}", hash);
    io::write_slice(&hash.0);
    // Leak memory, save cycles
    core::mem::forget((header, state));
}
