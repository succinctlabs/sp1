//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_recursion::stark::RiscvStark;
use sp1_recursion::stark::ShardProof;
use sp1_recursion::RecursiveVerifier;

use sp1_recursion::RISCV_STARK;

pub fn main() {
    type SC = sp1_recursion::utils::BabyBearBlake3;

    let config = SC::new();

    let machine = RISCV_STARK;

    // Read the proof from the input
    // let proof = sp1_zkvm::io::read::<ShardProof<SC>>();
}
