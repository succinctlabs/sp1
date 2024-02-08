#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use succinct_precompiles::io;
use zeth_lib::{
    builder::{BlockBuilderStrategy, EthereumStrategy},
    consts::ETH_MAINNET_CHAIN_SPEC,
    input::Input,
    EthereumTxEssence,
};

fn main() {
    println!("cycle-tracker-start: read input");
    let input = io::read::<Input<EthereumTxEssence>>();
    println!("cycle-tracker-end: read input");

    let (header, state) = EthereumStrategy::build_from(&ETH_MAINNET_CHAIN_SPEC, input).unwrap();

    let hash = header.hash();
    println!("Block hash: {:x}", hash);

    io::write_slice(&hash.0);
    core::mem::forget((header, state));
}
