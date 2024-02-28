//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_recursion::stark::RiscvStark;
use sp1_recursion::stark::ShardProof;
use sp1_recursion::utils::StarkUtils;
use sp1_recursion::RecursiveVerifier;

use sp1_recursion::RISCV_STARK;

pub fn main() {
    type SC = sp1_recursion::utils::BabyBearBlake3;

    let config = SC::new();

    // Read the proof from the input
    println!("cycle-tracker-start: read proof");
    let proof = sp1_zkvm::io::read::<ShardProof<SC>>();
    println!("cycle-tracker-end: read proof");

    println!("cycle-tracker-start: get a new challenger");
    let mut challenger = config.challenger();
    println!("cycle-tracker-end: get a new challenger");

    println!("cycle-tracker-start: verify proof");
    RecursiveVerifier::verify_shard(&RISCV_STARK, &mut challenger, &proof);
    println!("cycle-tracker-end: verify proof");
}
