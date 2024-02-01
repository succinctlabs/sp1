// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
