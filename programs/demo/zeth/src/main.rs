#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use zeth_lib::{
    builder::{BlockBuilderStrategy, EthereumStrategy},
    consts::ETH_MAINNET_CHAIN_SPEC,
    input::Input,
    EthereumTxEssence,
};

fn main() {
    println!("cycle-tracker-start: read input");
    let input = succinct_zkvm::io::read::<Input<EthereumTxEssence>>();
    println!("cycle-tracker-end: read input");

    let (header, state) = EthereumStrategy::build_from(&ETH_MAINNET_CHAIN_SPEC, input).unwrap();

    let hash = header.hash();
    println!("Block hash: {:x}", hash);

    succinct_zkvm::io::write_slice(&hash.0);
    core::mem::forget((header, state));
}
