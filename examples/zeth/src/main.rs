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
    let input = io::read::<Input<EthereumTxEssence>>();
    // Build the resulting block
    let (header, state) = EthereumStrategy::build_from(&ETH_MAINNET_CHAIN_SPEC, input)
        .expect("Failed to build the resulting block");
    // Output the resulting block's hash to the journal
    io::write(&header.hash());
    // Leak memory, save cycles
    core::mem::forget((header, state));
}
